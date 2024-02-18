using System;
using System.IO;
using System.Security.Cryptography;


public sealed class FileDecrypt
{
  public static readonly int MB = 1048576;
  public static readonly int GB = 1073741824;
  public static readonly int BlockSize = 88 * FileDecrypt.MB;
  public static readonly int BlockStep = 892 * FileDecrypt.MB;
  public static readonly int MaxEncSize = 10 * FileDecrypt.GB;

  private FileDecrypt()
  {
  }

  public static byte[] RSAEncrypt(
    byte[] data,
    string rsaPubKey)
  {
    using (RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider())
    {
      cryptoServiceProvider.FromXmlString(rsaPubKey);
      return cryptoServiceProvider.Encrypt(data, false);
    }
  }

  public static byte[] RSADecrypt(byte[] data, string rsaPrivKey)
  {
    using (RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider())
    {
      cryptoServiceProvider.FromXmlString(rsaPrivKey);
      return cryptoServiceProvider.Decrypt(data, false);
    }
  }

  public static void DecryptFile(string filePath)
  {
    int encKeyDataSize = 256;
    using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
    {
      using (FileStream fileStream = File.Open(filePath, FileMode.Open,
                                               FileAccess.ReadWrite,
                                               FileShare.None))
      {
        if (!fileStream.CanWrite)
          throw new Exception("[X] " + filePath + " can not write!");
        rijndaelManaged.Mode = CipherMode.CFB;
        rijndaelManaged.Padding = PaddingMode.Zeros;
        byte[] encKeyData = new byte[encKeyDataSize];
        fileStream.Seek((long) -encKeyDataSize, SeekOrigin.End);
        fileStream.Read(encKeyData, 0, encKeyDataSize);
        byte[] keyData = FileDecrypt.RSADecrypt(encKeyData,
                                                Config.RSAPrivKey);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        Array.Copy((Array) keyData, (Array) key, key.Length);
        Array.Copy((Array) keyData, key.Length, (Array) iv, 0, iv.Length);
        using (ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor(key,
                                                                            iv))
        {
          long origFileSize = fileStream.Length - (long) encKeyDataSize;
          fileStream.SetLength(origFileSize);
          if (origFileSize <= (long) FileDecrypt.BlockSize)
          {
            fileStream.Seek(0L, SeekOrigin.Begin);
            using (MemoryStream memoryStream = new MemoryStream())
            {
              using (CryptoStream destination = new CryptoStream((Stream) memoryStream,
                                                                 decryptor,
                                                                 CryptoStreamMode.Write))
              fileStream.CopyTo((Stream) destination);
              fileStream.Seek(0L, SeekOrigin.Begin);
              fileStream.Write(memoryStream.ToArray(), 0,
                               memoryStream.ToArray().Length);
            }
          }
          else
          {
            int offset = 0;
            while ((long) offset < origFileSize)
            {
              fileStream.Seek((long) offset, SeekOrigin.Begin);
              byte[] buffer = new byte[FileDecrypt.BlockSize];
              fileStream.Read(buffer, 0, FileDecrypt.BlockSize);
              using (MemoryStream memoryStream1 = new MemoryStream(buffer))
              {
                using (MemoryStream memoryStream2 = new MemoryStream())
                {
                  using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream2,
                                                                      decryptor,
                                                                      CryptoStreamMode.Write))
                  {
                    cryptoStream.Write(memoryStream1.ToArray(), 0,
                                       FileDecrypt.BlockSize);
                    fileStream.Seek((long) offset, SeekOrigin.Begin);
                    fileStream.Write(memoryStream2.ToArray(), 0,
                                     FileDecrypt.BlockSize);
                  }
                }
              }
              offset += FileDecrypt.BlockStep;
              if (offset >= FileDecrypt.MaxEncSize)
                break;
            }
          }
        }
      }
    }
    File.Move(filePath,
              filePath.Substring(0, filePath.LastIndexOf(".")) ?? "");
  }
}
