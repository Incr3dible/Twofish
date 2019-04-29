using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Twofish
{
    public sealed class TwofishManagedTransform : ICryptoTransform
    {
        public enum TwofishManagedTransformMode
        {
            Encrypt = 0,
            Decrypt = 1
        }

        private readonly TwofishImplementation _implementation;
        private readonly PaddingMode _paddingMode;
        private readonly TwofishManagedTransformMode _transformMode;

        private byte[]
            _paddingBuffer; // used to store last block block under decrypting as to work around CryptoStream implementation details.

        internal TwofishManagedTransform(byte[] key, CipherMode mode, byte[] iv,
            TwofishManagedTransformMode transformMode, PaddingMode paddingMode)
        {
            _transformMode = transformMode;
            _paddingMode = paddingMode;

            var key32 = new uint[key.Length / 4];
            Buffer.BlockCopy(key, 0, key32, 0, key.Length);

            if (iv != null)
            {
                var iv32 = new uint[iv.Length / 4];
                Buffer.BlockCopy(iv, 0, iv32, 0, iv.Length);
                _implementation = new TwofishImplementation(key32, iv32, mode);
            }
            else
            {
                _implementation = new TwofishImplementation(key32, null, mode);
            }
        }


        /// <summary>
        ///     Gets a value indicating whether the current transform can be reused.
        /// </summary>
        public bool CanReuseTransform => false;

        /// <summary>
        ///     Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        public bool CanTransformMultipleBlocks => true;

        /// <summary>
        ///     Gets the input block size (in bytes).
        /// </summary>
        public int InputBlockSize
            // block is always 128 bits
            =>
                16;

        /// <summary>
        ///     Gets the output block size (in bytes).
        /// </summary>
        public int OutputBlockSize
            // block is always 128 bits
            =>
                16;

        /// <summary>
        ///     Releases resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        ///     Transforms the specified region of the input byte array and copies the resulting transform to the specified region
        ///     of the output byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
        /// <param name="outputBuffer">The output to which to write the transform.</param>
        /// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
        [SuppressMessage("Microsoft.Usage", "CA2233:OperationsShouldNotOverflow",
            MessageId = "outputOffset+16",
            Justification = "Value will never cause the arithmetic operation to overflow.")]
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
            int outputOffset)
        {
            if (inputBuffer == null)
                throw new ArgumentNullException(nameof(inputBuffer), "Input buffer cannot be null.");

            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException(nameof(inputOffset), "Offset must be non-negative number.");

            if (inputCount <= 0 || inputCount % 16 != 0 || inputCount > inputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(inputCount), "Invalid input count.");

            if (inputBuffer.Length - inputCount < inputOffset)
                throw new ArgumentOutOfRangeException(nameof(inputCount), "Invalid input length.");

            if (outputBuffer == null)
                throw new ArgumentNullException(nameof(outputBuffer), "Output buffer cannot be null.");

            if (outputOffset + inputCount > outputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(outputOffset), "Insufficient buffer.");

            if (_transformMode == TwofishManagedTransformMode.Encrypt)
            {
                #region Encrypt

                for (var i = 0; i < inputCount; i += 16)
                    _implementation.BlockEncrypt(inputBuffer, inputOffset + i, outputBuffer, outputOffset + i);

                return inputCount;

                #endregion
            }

            #region Decrypt

            var bytesWritten = 0;

            if (_paddingBuffer != null)
            {
                _implementation.BlockDecrypt(_paddingBuffer, 0, outputBuffer, outputOffset);
                outputOffset += 16;
                bytesWritten += 16;
            }

            for (var i = 0; i < inputCount - 16; i += 16)
            {
                _implementation.BlockDecrypt(inputBuffer, inputOffset + i, outputBuffer, outputOffset);
                outputOffset += 16;
                bytesWritten += 16;
            }

            if (_paddingMode == PaddingMode.None)
            {
                _implementation.BlockDecrypt(inputBuffer, inputOffset + inputCount - 16, outputBuffer,
                    outputOffset);
                bytesWritten += 16;
            }
            else
            {
                // save last block without processing because decryption otherwise cannot detect padding in CryptoStream
                if (_paddingBuffer == null) _paddingBuffer = new byte[16];

                Buffer.BlockCopy(inputBuffer, inputOffset + inputCount - 16, _paddingBuffer, 0, 16);
            }

            return bytesWritten;

            #endregion
        }

        /// <summary>
        ///     Transforms the specified region of the specified byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the byte array to use as data.</param>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer == null)
                throw new ArgumentNullException(nameof(inputBuffer), "Input buffer cannot be null.");

            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException(nameof(inputOffset), "Offset must be non-negative number.");

            if (inputCount < 0 || inputCount > inputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(inputCount), "Invalid input count.");

            if (inputBuffer.Length - inputCount < inputOffset)
                throw new ArgumentOutOfRangeException(nameof(inputCount), "Invalid input length.");

            if (_transformMode == TwofishManagedTransformMode.Encrypt)
            {
                #region Encrypt

                int paddedLength;
                byte[] paddedInputBuffer;
                int paddedInputOffset;

                switch (_paddingMode)
                {
                    case PaddingMode.PKCS7:
                    {
                        paddedLength = inputCount / 16 * 16 + 16; // to round to next whole block
                        paddedInputBuffer = new byte[paddedLength];
                        paddedInputOffset = 0;
                        Buffer.BlockCopy(inputBuffer, inputOffset, paddedInputBuffer, 0, inputCount);
                        var added = (byte) (paddedLength - inputCount);
                        for (var i = inputCount; i < inputCount + added; i++) paddedInputBuffer[i] = added;
                        break;
                    }

                    case PaddingMode.Zeros:
                        paddedLength = (inputCount + 15) / 16 * 16; // to round to next whole block
                        paddedInputBuffer = new byte[paddedLength];
                        paddedInputOffset = 0;
                        Buffer.BlockCopy(inputBuffer, inputOffset, paddedInputBuffer, 0, inputCount);
                        break;

                    default:
                    {
                        if (inputCount % 16 != 0)
                            throw new ArgumentOutOfRangeException(nameof(inputCount),
                                "Invalid input count for a given padding.");

                        paddedLength = inputCount;
                        paddedInputBuffer = inputBuffer;
                        paddedInputOffset = inputOffset;
                        break;
                    }
                }

                var outputBuffer = new byte[paddedLength];

                for (var i = 0; i < paddedLength; i += 16)
                    _implementation.BlockEncrypt(paddedInputBuffer, paddedInputOffset + i, outputBuffer, i);

                return outputBuffer;

                #endregion
            }
            else
            {
                #region Decrypt

                if (inputCount % 16 != 0)
                    throw new ArgumentOutOfRangeException(nameof(inputCount), "Invalid input count.");

                var outputBuffer = new byte[inputCount + (_paddingBuffer != null ? 16 : 0)];
                var outputOffset = 0;

                if (_paddingBuffer != null)
                {
                    // process leftover padding buffer to keep CryptoStream happy
                    _implementation.BlockDecrypt(_paddingBuffer, 0, outputBuffer, 0);
                    outputOffset = 16;
                }

                for (var i = 0; i < inputCount; i += 16)
                    _implementation.BlockDecrypt(inputBuffer, inputOffset + i, outputBuffer, outputOffset + i);

                if (_paddingMode == PaddingMode.PKCS7)
                {
                    var padding = outputBuffer[outputBuffer.Length - 1];
                    if (padding < 1 || padding > 16) throw new CryptographicException("Invalid padding.");

                    for (var i = outputBuffer.Length - padding; i < outputBuffer.Length; i++)
                        if (outputBuffer[i] != padding)
                            throw new CryptographicException("Invalid padding.");

                    var newOutputBuffer = new byte[outputBuffer.Length - padding];
                    Buffer.BlockCopy(outputBuffer, 0, newOutputBuffer, 0, newOutputBuffer.Length);
                    return newOutputBuffer;
                }

                if (_paddingMode == PaddingMode.Zeros)
                {
                    var newOutputLength = outputBuffer.Length;
                    for (var i = outputBuffer.Length - 1; i >= outputBuffer.Length - 16; i--)
                        if (outputBuffer[i] != 0)
                        {
                            newOutputLength = i + 1;
                            break;
                        }

                    if (newOutputLength == outputBuffer.Length) return outputBuffer;

                    var newOutputBuffer = new byte[newOutputLength];
                    Buffer.BlockCopy(outputBuffer, 0, newOutputBuffer, 0, newOutputBuffer.Length);
                    return newOutputBuffer;
                }

                return outputBuffer;

                #endregion
            }
        }

        private void Dispose(bool disposing)
        {
            if (!disposing) return;

            _implementation.Dispose();
            if (_paddingBuffer != null) Array.Clear(_paddingBuffer, 0, _paddingBuffer.Length);
        }
    }
}