namespace PasswordGenerator
{
    public interface ISecureRandom
    {
        uint Next(uint x, uint y);
    }
}