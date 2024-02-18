using System;
using System.Runtime.InteropServices;


public sealed class Utils
{
  private Utils()
  {
  }

  [DllImport("kernel32.dll", EntryPoint = "CheckRemoteDebuggerPresent", SetLastError = true)]
  public static extern bool CheckRemoteDebuggerPresent(
    IntPtr hProcess,
    ref bool pbDebuggerPresent);
}
