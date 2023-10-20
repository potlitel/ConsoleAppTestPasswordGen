// See https://aka.ms/new-console-template for more information
//https://codereview.stackexchange.com/questions/224033/password-maker-in-c

using PasswordGenerator;

var generator = new PasswordGen(new PasswordGeneratorOptions
{
    MinimumNumberOfLowerCaseCharacters = 1,
    MinimumNumberOfNumericCharacters = 7,
    MinimumNumberOfUpperCaseCharacters = 5,
    OutputLength = 18,
    SpecialCharacters = new char[2] { '*', '_' },
});

Console.WriteLine(generator.Next());