using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;


public sealed class Decryption
{
  public bool ExtendedLog;

  private ConcurrentQueue<FileInfo> fileQueue = new ConcurrentQueue<FileInfo>();
  private List<Task> decryptionTasks = new List<Task>();
  private bool decryptionStarted;

  public void DecryptAll()
  {
    int numTasks = Environment.ProcessorCount * 2;
    for (int i = 0; i < numTasks; ++i)
      this.decryptionTasks.Add(new Task((Action) (() => this.DoDecrypt())));
    foreach (DriveInfo drive in DriveInfo.GetDrives())
      this.DecryptDrive(drive);
    this.decryptionStarted = true;
    foreach (Task task in this.decryptionTasks)
      task.Start();
    Task.WaitAll(this.decryptionTasks.ToArray());
  }

  public void DecryptPath(string path)
  {
    if (File.Exists(path))
    {
      try
      {
        this.DecryptFile(new FileInfo(path));
      }
      catch (Exception e)
      {
      }
    }
    else
    {
      if (!Directory.Exists(path))
        return;
      int numTasks = Environment.ProcessorCount * 2;
      for (int i = 0; i < numTasks; ++i)
        this.decryptionTasks.Add(new Task((Action) (() => this.DoDecrypt())));
      this.EnumFiles(new DirectoryInfo(path));
      this.decryptionStarted = true;
      foreach (Task task in this.decryptionTasks)
        task.Start();
      Task.WaitAll(this.decryptionTasks.ToArray());
    }
  }

  private void DecryptDrive(DriveInfo driveInfo)
  {
    if (!driveInfo.IsReady)
      return;
    Console.WriteLine("[*] " + driveInfo.Name + " ");
    foreach (DirectoryInfo dir in driveInfo.RootDirectory.GetDirectories())
      this.EnumFiles(dir);
  }

  private void EnumFiles(DirectoryInfo dirInfo)
  {
    try
    {
      DirectoryInfo[] directories = dirInfo.GetDirectories();
      if (directories != null)
      {
        foreach (DirectoryInfo dir in directories)
          this.EnumFiles(dir);
      }
      foreach (FileInfo file in dirInfo.GetFiles())
        this.fileQueue.Enqueue(file);
    }
    catch (Exception e)
    {
    }
  }

  private void DoDecrypt()
  {
    while (!this.decryptionStarted || !this.fileQueue.IsEmpty)
    {
      FileInfo fileInfo = (FileInfo) null;
      if (this.fileQueue.TryDequeue(out fileInfo))
        this.DecryptFile(fileInfo);
    }
  }

  private void DecryptFile(FileInfo fileInfo)
  {
    if (!fileInfo.FullName.ToLower().Contains("." + Config.RansomExt))
      return;
    try
    {
      FileDecrypt.DecryptFile(fileInfo.FullName);
      if (this.ExtendedLog)
        return;
      Console.WriteLine("[+] " + fileInfo.FullName);
    }
    catch (Exception e)
    {
    }
  }
}
