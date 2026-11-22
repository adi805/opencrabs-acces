package com.termux.terminal;

import android.util.Base64;

import java.util.Arrays;

/**
 * An iTerm image received via `OSC 1337`.
 *
 * - https://iterm2.com/documentation-images.html
 */
public class ITermImage {

    public static final String LOG_TAG = "ITermImage";



    /** The {@link Enum} that defines {@link ITermImage} state. */
    public enum ImageState {

        INIT("init", 0),
        ARGUMENTS_READ("arguments_read", 1),
        IMAGE_READING("image_reading", 2),
        IMAGE_READ("image_read", 3),
        IMAGE_DECODED("image_decoded", 4),
        FAILED("Failed", 5);

        private final String name;
        private final int value;

        ImageState(final String name, final int value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public int getValue() {
            return value;
        }

    }



    protected final TerminalSessionClient mClient;

    protected final boolean mIsMultipart;

    protected int mWidth = -1;
    protected int mHeight = -1;

    protected boolean mInline = false;

    protected boolean mPreserveAspectRatio = true;

    protected final StringBuilder mEncodedImage = new StringBuilder(/* Initial capacity. */ 4096);
    /**
     * Ceiling on the base64 text one image may accumulate, checked BEFORE an append.
     *
     * <p>The OSC parser limits how big a single command may be, but nothing limited
     * the total: a stream of {@code FilePart} commands kept appending to
     * {@link #mEncodedImage} until the heap was gone. Catching OutOfMemoryError is
     * not a fix, because by then the app is already unresponsive; the cap has to
     * refuse the append that would cross it. 8 MiB of base64 is 6 MiB of image,
     * well past any screenshot this terminal is asked to render.
     */
    protected static final int MAX_ENCODED_IMAGE_CHARS = 8 * 1024 * 1024;
    protected byte[] mDecodedImage;

    /** The current state of the {@link ImageState}. */
    protected ImageState mCurrentState = ImageState.INIT;
    /** The previous state of the {@link ImageState}. */
    protected ImageState mPreviousState = ImageState.INIT;



    protected ITermImage(TerminalSessionClient client, boolean isMultiPart) {
        mClient = client;

        mIsMultipart = isMultiPart;
    }



    public TerminalSessionClient getClient() {
        return mClient;
    }


    public boolean isMultipart() {
        return mIsMultipart;
    }


    public int getWidth() {
        return mWidth;
    }

    public int getHeight() {
        return mHeight;
    }


    public boolean isInline() {
        return mInline;
    }


    public boolean shouldPreserveAspectRatio() {
        return mPreserveAspectRatio;
    }


    public String getEncodedImage() {
        return mEncodedImage.toString();
    }

    public byte[] getDecodedImage() {
        return mDecodedImage;
    }


    public synchronized ImageState getCurrentState() {
        return mCurrentState;
    }

    public synchronized ImageState getPreviousState() {
        return mPreviousState;
    }


    protected synchronized boolean setState(ImageState newState) {
        // The state transition cannot go back or change if already at `ImageState.IMAGE_DECODED`
        if (newState.getValue() < mCurrentState.getValue() || mCurrentState == ImageState.IMAGE_DECODED) {
            Logger.logError(mClient, LOG_TAG,
                "Invalid image state transition from \"" + mCurrentState.getName() + "\" to " +  "\"" + newState.getName() + "\"");
            return false;
        }

        // The `ImageState.FAILED` can be set again, like to add more errors, but we don't update
        // `mPreviousState` with the `mCurrentState` value if its at `ImageState.FAILED` to
        // preserve the last valid state.
        if (mCurrentState != ImageState.FAILED)
            mPreviousState = mCurrentState;

        mCurrentState = newState;
        return  true;
    }


    protected synchronized boolean setStateFailed(String error) {
        if (error != null) {
            Logger.logError(mClient, LOG_TAG, error);
        }
        return setState(ImageState.FAILED);
    }


    protected synchronized boolean ensureState(ImageState expectedState) {
        return ensureState(expectedState, null);
    }

    protected synchronized boolean ensureState(ImageState expectedState, String functionName) {
        if (mCurrentState != expectedState) {
            Logger.logError(mClient, LOG_TAG,
                "The current image state is \"" + mCurrentState.getName() + "\" but expected \"" + expectedState.getName() + "\"" +
                (functionName != null ? " while calling '" + functionName : "'") +
                " for " + (!mIsMultipart ? "singlepart" : "multipart") + " image");
            return false;
        }
        return true;
    }


    public synchronized boolean isArgumentsRead() {
        return mCurrentState == ImageState.ARGUMENTS_READ;
    }

    public synchronized boolean isImageReading() {
        return mCurrentState == ImageState.IMAGE_READING;
    }

    public synchronized boolean isImageRead() {
        return mCurrentState == ImageState.IMAGE_READ;
    }

    public synchronized boolean isImageDecoded() {
        return mCurrentState == ImageState.IMAGE_DECODED;
    }



    public synchronized int readArguments(TerminalEmulator terminalEmulator, StringBuilder oscArgs, int index) {
        if (!ensureState(ImageState.INIT, "ImageState.readArguments()")) {
            return -1;
        }

        boolean lastParam = false;
        while (index < oscArgs.length()) {
            char ch = oscArgs.charAt(index);
            // End of optional arguments.
            if (ch == ':' && !mIsMultipart) {
                break;
            } else if (ch == ' ') {
                index++;
                continue;
            }

            int keyEndIndex = oscArgs.indexOf("=", index);
            if (keyEndIndex == -1) {
                setStateFailed("The key for an argument not found after index " + index + " in osc argument string: " + oscArgs);
                return -1;
            }
            String argKey = oscArgs.substring(index, keyEndIndex);

            int valueEndIndex = oscArgs.indexOf(";", keyEndIndex);
            if (valueEndIndex == -1) {
                if (!mIsMultipart) {
                    // The last key value for `File=` command arguments may end with a colon `:` instead of a semi colon `;`.
                    valueEndIndex = oscArgs.indexOf(":", keyEndIndex);
                    if (valueEndIndex == -1) {
                        setStateFailed("The value for an argument not found after index " + index + " in osc argument string: " + oscArgs);
                        return -1;
                    } else {
                        index = valueEndIndex;
                        lastParam = true;
                    }
                } else {
                    // The last key value for `MultipartFile=` command arguments may end without a semi colon `;`.
                    valueEndIndex = oscArgs.length();
                    index = valueEndIndex;
                }
            } else {
                index = valueEndIndex + 1;
            }

            if (valueEndIndex <= keyEndIndex) {
                setStateFailed("The argument key end index " + keyEndIndex +
                    " is <= value end index " + valueEndIndex + " in osc argument string: " + oscArgs);
                return -1;
            }

            String argValue = oscArgs.substring(keyEndIndex + 1, valueEndIndex);

            if (argKey.equalsIgnoreCase("inline")) {
                mInline = argValue.equals("1");
            }
            else if (argKey.equalsIgnoreCase("preserveAspectRatio")) {
                mPreserveAspectRatio = !argValue.equals("0");
            }
            else if (argKey.equalsIgnoreCase("width")) {
                double factor = terminalEmulator.getCellWidthPixels();
                int intValueEndIndex = argValue.length();
                if (argValue.endsWith("px")) {
                    factor = 1;
                    intValueEndIndex -= 2;
                } else if (argValue.endsWith("%")) {
                    factor = 0.01 * terminalEmulator.getCellWidthPixels() * terminalEmulator.getColumns();
                    intValueEndIndex -= 1;
                }
                try {
                    mWidth = (int) (factor * Integer.parseInt(argValue.substring(0, intValueEndIndex)));
                } catch (Exception e) {
                }
            }
            else if (argKey.equalsIgnoreCase("height")) {
                double factor = terminalEmulator.getCellHeightPixels();
                int intValueEndIndex = argValue.length();
                if (argValue.endsWith("px")) {
                    factor = 1;
                    intValueEndIndex -= 2;
                } else if (argValue.endsWith("%")) {
                    factor = 0.01 * terminalEmulator.getCellHeightPixels() * terminalEmulator.getRows();
                    intValueEndIndex -= 1;
                }
                try {
                    mHeight = (int) (factor * Integer.parseInt(argValue.substring(0, intValueEndIndex)));
                } catch (Exception e) {
                }
            } else {
                // `name` and `size` keys are not supported.
            }

            if (lastParam) {
                break;
            }
        }

        setState(ImageState.ARGUMENTS_READ);

        return index;
    }


    public synchronized boolean readImage(StringBuilder oscArgs, int index) {
        if (!mIsMultipart) {
            if (!ensureState(ImageState.ARGUMENTS_READ, "ImageState.readImage()")) {
                return false;
            }

            if (index < oscArgs.length()) {
                int colonIndex = oscArgs.indexOf(":", index);
                if (colonIndex >= 0 && colonIndex + 1 < oscArgs.length()) {
                    setState(ImageState.IMAGE_READING);
                    int imageStartIndex = colonIndex + 1;

                    if (!appendEncoded(oscArgs.substring(imageStartIndex),
                            "Collecting singlepart image")) {
                        return false;
                    }

                    setState(ImageState.IMAGE_READ);
                    return true;
                }
            }

            setStateFailed("Failed to read singlepart image from index " + index + " in osc argument string: " + oscArgs);
            return false;
        } else {
            if (mCurrentState != ImageState.IMAGE_READING &&
                !ensureState(ImageState.ARGUMENTS_READ, "ImageState.readImage()")) {
                return false;
            }

            // An empty `FilePart=` command could be received as well, so change state before `if` below.
            setState(ImageState.IMAGE_READING);

            if (index < oscArgs.length()) {
                if (!appendEncoded(oscArgs.substring(index), "Collecting multipart image")) {
                    return false;
                }
                return true;
            }

            setStateFailed("Failed to read multipart image" + " in osc argument string: " + oscArgs);
            return false;
        }
    }

    /**
     * Append one chunk of base64 text, refusing the chunk that would cross the cap.
     *
     * <p>Guarding the append rather than the catch: an OutOfMemoryError arrives after
     * the heap is already gone, and this process is the terminal the user is looking
     * at. A chunk that would exceed {@link #MAX_ENCODED_IMAGE_CHARS} discards what
     * was collected and fails the image, so the next command starts from empty.
     *
     * @return false when the image was discarded, in which case the state is already
     *         {@link ImageState#FAILED}
     */
    private boolean appendEncoded(String chunk, String what) {
        if (chunk == null || chunk.isEmpty()) {
            return true;
        }
        if (mEncodedImage.length() + chunk.length() > MAX_ENCODED_IMAGE_CHARS) {
            mEncodedImage.setLength(0);
            mEncodedImage.trimToSize();
            setStateFailed(what + " exceeds " + MAX_ENCODED_IMAGE_CHARS
                + " base64 characters, image discarded");
            return false;
        }
        try {
            mEncodedImage.append(chunk);
            return true;
        } catch (Throwable t) {
            if (t instanceof OutOfMemoryError) System.gc();
            mEncodedImage.setLength(0);
            setStateFailed(what + " in osc argument string failed: " + t.getMessage());
            return false;
        }
    }

    public synchronized boolean setMultiPartImageRead() {
        if (!mIsMultipart) {
            Logger.logError(mClient, LOG_TAG, "Attempting to call 'ImageState.setMultiPartImageRead()' for a singlepart image");
            return false;
        }

        // A `FileEnd` command may have been received without a `FilePart=` command preceding it.
        if (!ensureState(ImageState.IMAGE_READING, "ImageState.setMultiPartImageRead()")) {
            return false;
        }

        setState(ImageState.IMAGE_READ);
        return true;
    }


    public synchronized boolean decodeImage() {
        if (!ensureState(ImageState.IMAGE_READ, "ImageState.decodeImage()")) {
            return false;
        }

        String encodedImageString = null;
        try {
            if (mEncodedImage.length() < 1) {
                setStateFailed("Cannot decoded an empty image");
                return false;
            }

            while (mEncodedImage.length() % 4 != 0) {
                mEncodedImage.append('=');
            }

            encodedImageString = mEncodedImage.toString();

            // Clear original encoded image from memory as it is no longer needed.
            mEncodedImage.setLength(0);
            mEncodedImage.trimToSize();

            mDecodedImage = Base64.decode(encodedImageString, Base64.DEFAULT);
            if (mDecodedImage == null || mDecodedImage.length < 2) {
                setStateFailed("The decoded image is not valid: " + Arrays.toString(mDecodedImage) + "\nimage: " + encodedImageString);
                return false;
            }

            setState(ImageState.IMAGE_DECODED);
            return true;
        } catch (Throwable t) {
            if (t instanceof OutOfMemoryError) {
                Logger.logError(mClient, LOG_TAG, "Failed to decode image: " + t.getMessage());
                System.gc();
            } else {
                Logger.logStackTraceWithMessage(mClient, LOG_TAG, "Failed to decode image: " + encodedImageString, t);
            }
            setStateFailed(null);
            return false;
        }
    }

}
