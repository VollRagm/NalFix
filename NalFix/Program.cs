using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NalFix
{
    public class Program
    {
        static string SystemRoot;

        static byte[] DeviceName = { 0x44, 0x0, 0x65, 0x0, 0x76, 0x0, 0x69, 0x0, 0x63, 0x0, 0x65, 0x0, 0x5C, 0x0, 0x4E, 0x0, 0x61, 0x0, 0x6C, 0x0, 0x0, 0x0 };

        static void Main(string[] args)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    Log.Error("No administrator permissions");
                    Console.ReadLine();
                    return;
                }
            }

            Log.Info("NalFix by VollRagm");

            if (!IsNalInUse())
            {
                Log.Critical("Device/Nal is not in use!");
                Console.ReadLine();
                return;
            }

            SystemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            Log.Info("Enumerating all running kernel mode services...");
            var kernelServices = GetDriverPaths();

            Log.Info("Scanning for Device/Nal...");

            bool found = false;

            foreach (var driver in kernelServices)
            {
                var val = DoesFileContainNal(driver.Value);
                if (val)
                {
                    found = true;
                    Log.Critical($"{driver.Key} contains Device/Nal, removing service...");
                   
                    StopAndRemoveService(driver.Key);
                    Thread.Sleep(200);
                    if (IsNalInUse())
                    {
                        var forceful = Log.QueryYesNo("Device/Nal is still in use, do you want to try to forcefully remove the service? (y/n): ");
                        if (forceful)
                        {
                            var success = StopAndRemoveForcefully(driver.Key);
                            if(!success)
                            {
                                Log.Error("Couldn't delete service forcefully.");
                                Console.ReadLine();
                                return;
                            }
                        }
                    }
                    else
                    {
                        Log.Critical("Device/Nal is not in use anymore!");
                    }
                }
            }

            if (found)
            {
                Log.Info("Done.");
            }
            else
            {
                Log.Error("Driver wasn't found.");
            }

            Console.ReadLine();
        }

        static Dictionary<string, string> GetDriverPaths()
        {
            var servicesKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\");
            var servicesNames = servicesKey.GetSubKeyNames();

            Dictionary<string, string> paths = new Dictionary<string, string>();

            Parallel.ForEach(servicesNames, (service) =>
            {
                var serviceKey = servicesKey.OpenSubKey(service);
                var type = Convert.ToUInt32(serviceKey.GetValue("Type", 0));
                if (type == 0x1)
                { //Kernel service
                    if (IsServiceStopped(service)) return;
                    string path = (string)serviceKey.GetValue("ImagePath", "");
                    if (!string.IsNullOrEmpty(path))
                        paths.Add(service, ProcessPath(path));
                }
            });

         
            return paths;
        }

        static bool IsNalInUse()
        {
            long handle = CreateFile("\\\\.\\Nal", EFileAccess.AnyAccess, 0, IntPtr.Zero, EFileMode.OpenExisting, 0x80, IntPtr.Zero).ToInt64();
            if (handle != 0 && handle != -1)
            {
                CloseHandle((IntPtr)handle);
                return true;
            }
            return false;
        }

        static bool DoesFileContainNal(string file)
        {
            if (File.Exists(file))
            {
                var bytes = File.ReadAllBytes(file);
                if(PatternScan(bytes, DeviceName) != -1)
                {
                    return true;
                }
            }
            return false;
        }

        static bool IsServiceStopped(string service)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("sc", "query " + service);
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                var proc = Process.Start(psi);
                proc.WaitForExit();
                var output = proc.StandardOutput.ReadToEnd();
                if (output.Contains("STOPPED")) return true;
                else return false;

            }
            catch
            {
                return false;
            }
        }

        static string ProcessPath(string path)
        {
            path = path.Replace("\\??\\", "");

            if (path.StartsWith("system32"))
                path = path.Replace("system32", SystemRoot + "\\system32");

            if (path.StartsWith("System32"))
                path = path.Replace("System32", SystemRoot + "\\System32");

            if (path.StartsWith("\\SystemRoot"))
                path = path.Replace("\\SystemRoot", SystemRoot);

            return path;
        }

        static void StopAndRemoveService(string serivceName)
        {
            Process.Start("sc", $"stop {serivceName}");
            Process.Start("sc", $"remove {serivceName}");
        }

        //https://stackoverflow.com/questions/283456/byte-array-pattern-search
        static int PatternScan(byte[] src, byte[] pattern)
        {
            int maxFirstCharSlot = src.Length - pattern.Length + 1;
            for (int i = 0; i < maxFirstCharSlot; i++)
            {
                if (src[i] != pattern[0]) // compare only first byte
                    continue;

                // found a match on first byte, now try to match rest of the pattern
                for (int j = pattern.Length - 1; j >= 1; j--)
                {
                    if (src[i + j] != pattern[j]) break;
                    if (j == 1) return i;
                }
            }
            return -1;
        }

        public static bool StopAndRemoveForcefully(string name)
        {
            int status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, true, ADJUST_PRIVILEGE_TYPE.AdjustCurrentProcess, out bool wasEnabled);
            if (!NT_SUCCESS(status))
            {
                Log.Error("RtlAdjustPrivilege failed -> " + status.ToString("X8"));
                return false;
            }

            string fullRegPath = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + name;
            RtlInitUnicodeString(out UNICODE_STRING serviceString, fullRegPath);
            status = NtUnloadDriver(ref serviceString);

            if(!NT_SUCCESS(status))
            {
                Log.Error("NtUnloadDriver failed -> " + status.ToString("X8"));
                return false;
            }

            Log.Info("NtUnloadDriver -> " + status.ToString("X8"));

            if (NT_SUCCESS(status))
            {
                try
                {
                    Registry.LocalMachine.DeleteSubKey("SYSTEM\\CurrentControlSet\\Services\\" + name);
                    Log.Info("Deleted registry key.");
                    return true;
                }
                catch
                {
                    Log.Error("Couldn't delete registry key.");
                    return false;
                }
            }
            return false;
        }

        public const int SE_LOAD_DRIVER_PRIVILEGE = 10;

        public enum ADJUST_PRIVILEGE_TYPE
        {
            AdjustCurrentProcess,
            AdjustCurrentThread
        };

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int RtlAdjustPrivilege(int Privilege, bool Enable,
             ADJUST_PRIVILEGE_TYPE CurrentThread, out bool Enabled);

        [DllImport("ntdll.dll")]
        public static extern int NtUnloadDriver(ref UNICODE_STRING DriverName);

        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(out UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
            [MarshalAs(UnmanagedType.LPTStr)] string filename,
            [MarshalAs(UnmanagedType.U4)] EFileAccess access,
            uint share,
            IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
            [MarshalAs(UnmanagedType.U4)] EFileMode creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public ulong Buffer;
        };

        static bool NT_SUCCESS(int status)
        {
            return status >= 0;
        }


        [Flags]
        public enum EFileAccess : uint
        {
            AnyAccess = 0x0,
            ReadAccess = 0x1,
            WriteAccess = 0x2,
            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            ReadWrite = GenericRead | GenericWrite
        }

        public enum EFileMode : uint
        {
            CreateNew = 0x1,
            CreateAlways = 0x2,
            OpenExisting = 0x3,
            OpenAlways = 0x4
        }
    }
}
