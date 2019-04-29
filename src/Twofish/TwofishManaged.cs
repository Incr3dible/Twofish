using System;
using System.Security.Cryptography;

// ReSharper disable ThreadStaticFieldHasInitializer

namespace Twofish
{
    public sealed class TwofishManaged : SymmetricAlgorithm
    {
        /// <summary>
        ///     Initializes a new instance.
        /// </summary>
        public TwofishManaged()
        {
            KeySizeValue = 256;
            BlockSizeValue = 128;
            FeedbackSizeValue = BlockSizeValue;
            LegalBlockSizesValue = new[] {new KeySizes(128, 128, 0)};
            LegalKeySizesValue = new[] {new KeySizes(128, 256, 64)};

            base.Mode = CipherMode.CBC; // same as default
            base.Padding = PaddingMode.PKCS7;
        }


        /// <summary>
        ///     Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        public override CipherMode Mode
        {
            get => base.Mode;
            set
            {
                if (value != CipherMode.CBC && value != CipherMode.ECB)
                    throw new CryptographicException("Cipher mode is not supported.");

                base.Mode = value;
            }
        }

        /// <summary>
        ///     Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        public override PaddingMode Padding
        {
            get => base.Padding;
            set
            {
                if (value != PaddingMode.None && value != PaddingMode.PKCS7 && value != PaddingMode.Zeros)
                    throw new CryptographicException("Padding mode is not supported.");

                base.Padding = value;
            }
        }


        /// <summary>
        ///     Creates a symmetric decryptor object.
        /// </summary>
        /// <param name="rgbKey">The secret key to be used for the symmetric algorithm. The key size must be 128, 192, or 256 bits.</param>
        /// <param name="rgbIv">The IV to be used for the symmetric algorithm.</param>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIv)
        {
            if (rgbKey == null) throw new ArgumentNullException(nameof(rgbKey), "Key cannot be null.");

            if (rgbKey.Length != KeySize / 8)
                throw new ArgumentOutOfRangeException(nameof(rgbKey), "Key size mismatch.");

            if (Mode != CipherMode.CBC)
                return NewEncryptor(rgbKey, Mode, rgbIv, TwofishManagedTransform.TwofishManagedTransformMode.Decrypt);

            if (rgbIv.Length != 16) throw new ArgumentOutOfRangeException("rgbIV", "Invalid IV size.");

            return NewEncryptor(rgbKey, Mode, rgbIv, TwofishManagedTransform.TwofishManagedTransformMode.Decrypt);
        }

        /// <summary>
        ///     Creates a symmetric encryptor object.
        /// </summary>
        /// <param name="rgbKey">The secret key to be used for the symmetric algorithm. The key size must be 128, 192, or 256 bits.</param>
        /// <param name="rgbIv">The IV to be used for the symmetric algorithm.</param>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIv)
        {
            if (rgbKey == null) throw new ArgumentNullException(nameof(rgbKey), "Key cannot be null.");

            if (rgbKey.Length != KeySize / 8)
                throw new ArgumentOutOfRangeException(nameof(rgbKey), "Key size mismatch.");

            if (Mode != CipherMode.CBC)
                return NewEncryptor(rgbKey, Mode, rgbIv, TwofishManagedTransform.TwofishManagedTransformMode.Encrypt);

            if (rgbIv.Length != 16) throw new ArgumentOutOfRangeException(nameof(rgbIv), "Invalid IV size.");

            return NewEncryptor(rgbKey, Mode, rgbIv, TwofishManagedTransform.TwofishManagedTransformMode.Encrypt);
        }

        /// <summary>
        ///     Generates a random initialization vector to be used for the algorithm.
        /// </summary>
        public override void GenerateIV()
        {
            IVValue = new byte[FeedbackSizeValue / 8];
            Rng.GetBytes(IVValue);
        }

        /// <summary>
        ///     Generates a random key to be used for the algorithm.
        /// </summary>
        public override void GenerateKey()
        {
            KeyValue = new byte[KeySizeValue / 8];
            Rng.GetBytes(KeyValue);
        }


        #region Private

        [ThreadStatic] private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        private ICryptoTransform NewEncryptor(byte[] rgbKey, CipherMode mode, byte[] rgbIv,
            TwofishManagedTransform.TwofishManagedTransformMode encryptMode)
        {
            if (rgbKey == null)
            {
                rgbKey = new byte[KeySize / 8];
                Rng.GetBytes(rgbKey);
            }

            if (mode == CipherMode.ECB || rgbIv != null)
                return new TwofishManagedTransform(rgbKey, mode, rgbIv, encryptMode, Padding);

            rgbIv = new byte[KeySize / 8];
            Rng.GetBytes(rgbIv);

            return new TwofishManagedTransform(rgbKey, mode, rgbIv, encryptMode, Padding);
        }

        #endregion
    }
}