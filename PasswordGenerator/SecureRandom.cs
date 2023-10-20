using System.Security.Cryptography;

namespace PasswordGenerator
{
    public sealed class SecureRandom : ISecureRandom
    {
        private static readonly RandomNumberGenerator DefaultRandomNumberGenerator = new RNGCryptoServiceProvider();

        public static SecureRandom DefaultInstance => new SecureRandom(DefaultRandomNumberGenerator);

        private readonly RandomNumberGenerator m_randomNumberGenerator;

        public SecureRandom(RandomNumberGenerator randomNumberGenerator)
        {
            if (null == randomNumberGenerator)
            {
                throw new ArgumentNullException(paramName: nameof(randomNumberGenerator));
            }

            m_randomNumberGenerator = randomNumberGenerator;
        }

        public byte[] GetBytes(byte[] buffer)
        {
            m_randomNumberGenerator.GetBytes(buffer);

            return buffer;
        }

        public byte[] GetBytes(int count) => GetBytes(new byte[count]);

        public uint Next() => BitConverter.ToUInt32(GetBytes(sizeof(uint)), 0);

        public uint Next(uint x, uint y)
        {
            if (x > y)
            {
                var z = x;

                x = y;
                y = z;
            }

            var range = (y - x);

            if (range == 0)
            {
                return x;
            }
            else if (range == uint.MaxValue)
            {
                return Next();
            }
            else
            {
                return (Next(exclusiveHigh: range) + x);
            }
        }

        private uint Next(uint exclusiveHigh)
        {
            var range = (uint.MaxValue - (((uint.MaxValue % exclusiveHigh) + 1) % exclusiveHigh));
            var result = 0U;

            do
            {
                result = Next();
            } while (result > range);

            return (result % exclusiveHigh);
        }
    }

    public sealed class PasswordGeneratorOptions
    {
        private static readonly char[] DefaultSpecialChars = new[] { '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '=', '`', '~', '_', '+', ',', '.', '\'', '"', ';', ':', '?', '|', '/', '\\', '[', ']', '{', '}', '<', '>' };

        public int MinimumNumberOfNumericCharacters { get; set; }
        public int MinimumNumberOfLowerCaseCharacters { get; set; }
        public int MinimumNumberOfSpecialCharacters { get; set; }
        public int MinimumNumberOfUpperCaseCharacters { get; set; }
        public int OutputLength { get; set; }
        public ISecureRandom RandomNumberGenerator { get; set; }
        public IReadOnlyList<char> SpecialCharacters { get; set; }

        public PasswordGeneratorOptions()
        {
            MinimumNumberOfLowerCaseCharacters = 0;
            MinimumNumberOfNumericCharacters = 0;
            MinimumNumberOfSpecialCharacters = 0;
            MinimumNumberOfUpperCaseCharacters = 0;
            RandomNumberGenerator = SecureRandom.DefaultInstance;
            SpecialCharacters = DefaultSpecialChars;
        }
    }

    public sealed class PasswordGen
    {
        private readonly Func<char> m_getAsciiLetterLowerCase;
        private readonly Func<char> m_getAsciiLetterUpperCase;
        private readonly Func<char> m_getAsciiNumeric;
        private readonly Func<char> m_getAsciiSpecial;
        private readonly PasswordGeneratorOptions m_options;

        public PasswordGen(PasswordGeneratorOptions options)
        {
            if (options.OutputLength < (options.MinimumNumberOfLowerCaseCharacters + options.MinimumNumberOfNumericCharacters + options.MinimumNumberOfSpecialCharacters + options.MinimumNumberOfUpperCaseCharacters))
            {
                throw new ArgumentOutOfRangeException(message: "output length must be greater than or equal to the sum of all MinimumNumber* properties", actualValue: options.OutputLength, paramName: nameof(options.OutputLength));
            }

            var randomNumberGenerator = options.RandomNumberGenerator;
            var specialCharacters = options.SpecialCharacters;

            m_getAsciiLetterLowerCase = () => ((char)randomNumberGenerator.Next(97, 123));
            m_getAsciiLetterUpperCase = () => ((char)randomNumberGenerator.Next(65, 91));
            m_getAsciiNumeric = () => ((char)randomNumberGenerator.Next(48, 58));
            m_getAsciiSpecial = () => specialCharacters[(int)randomNumberGenerator.Next(0U, ((uint)specialCharacters.Count))];
            m_options = options;
        }

        public string Next()
        {
            var index = 0;
            var length = m_options.OutputLength;
            var randomNumberGenerator = m_options.RandomNumberGenerator;
            var result = new char[length];
            var useSpecial = (0 < m_options.SpecialCharacters.Count);

            for (var i = 0; (i < m_options.MinimumNumberOfLowerCaseCharacters); i++)
            {
                result[index++] = m_getAsciiLetterLowerCase();
            }

            for (var i = 0; (i < m_options.MinimumNumberOfNumericCharacters); i++)
            {
                result[index++] = m_getAsciiNumeric();
            }

            for (var i = 0; (i < m_options.MinimumNumberOfSpecialCharacters); i++)
            {
                result[index++] = m_getAsciiSpecial();
            }

            for (var i = 0; (i < m_options.MinimumNumberOfUpperCaseCharacters); i++)
            {
                result[index++] = m_getAsciiLetterUpperCase();
            }

            for (var i = index; (i < length); i++)
            {
                char c;

                switch (randomNumberGenerator.Next(0U, (useSpecial ? 4U : 3U)))
                {
                    case 3U:
                        c = m_getAsciiSpecial();
                        break;

                    case 2U:
                        c = m_getAsciiNumeric();
                        break;

                    case 1U:
                        c = m_getAsciiLetterUpperCase();
                        break;

                    case 0U:
                        c = m_getAsciiLetterLowerCase();
                        break;

                    default:
                        throw new InvalidOperationException();
                }

                result[i] = c;
            }

            FisherYatesShuffle(randomNumberGenerator, result);

            return new string(result);
        }

        private static void SwapRandom<T>(ISecureRandom randomNumberGenerator, IList<T> list, uint indexLowerBound, uint indexUpperBound)
        {
            var randomIndex = randomNumberGenerator.Next(indexLowerBound, indexUpperBound);
            var tempValue = list[(int)randomIndex];

            list[(int)randomIndex] = list[(int)indexUpperBound];
            list[(int)indexUpperBound] = tempValue;
        }

        private static void FisherYatesShuffle<T>(ISecureRandom randomNumberGenerator, IList<T> list)
        {
            var length = list.Count;
            var offset = 0U;

            while (offset < length)
            {
                SwapRandom(randomNumberGenerator, list, 0U, offset++);
            }
        }
    }
}