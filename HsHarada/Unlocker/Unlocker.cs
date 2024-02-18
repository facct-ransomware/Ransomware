using System;


internal class Unlocker
{
  private static void Main(string[] args)
  {
    bool extendedLog = false;
    string path = "all".Equals(args[0]) ? (string) null : args[0];
    if (args.Length > 1)
      extendedLog = "-s".Equals(args[1]);
    Unlocker.Decrypt(path, extendedLog);
  }

  private static void Decrypt(string path = null, bool extendedLog = false)
  {
    Decryption decryption = new Decryption()
    {
      ExtendedLog = extendedLog
    };
    if (string.IsNullOrEmpty(path))
      decryption.DecryptAll();
    else
      decryption.DecryptPath(path);
    Console.WriteLine("===== OVER =====");
  }
}
