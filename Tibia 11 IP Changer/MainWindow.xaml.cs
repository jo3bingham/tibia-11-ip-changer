using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Windows;
using Tibia.Utilities;

namespace Tibia
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            uxClientPath.Text = Constants.DefaultClientPath;
        }

        private void uxBrowse_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new System.Windows.Forms.OpenFileDialog() { Filter = "Tibia Client (*.exe)|*.exe" };
            openFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            if (openFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                uxClientPath.Text = openFileDialog.FileName;
            }
        }

        private void uxApply_Click(object sender, RoutedEventArgs e)
        {
            if (uxClientPath.Text == string.Empty 
                || !uxClientPath.Text.Contains(".exe")
                || !File.Exists(uxClientPath.Text))
            {
                MessageBox.Show("Client path is not valid.");
                return;
            }

            var process = Process.Start(uxClientPath.Text);
            process.WaitForInputIdle();
            while (process.MainWindowHandle == IntPtr.Zero)
            {
                process.Refresh();
                Thread.Sleep(5);
            }

            var baseAddress = (uint)process.MainModule.BaseAddress.ToInt32();
            var processHandle = WinAPI.OpenProcess((WinAPI.PROCESS_VM_READ | WinAPI.PROCESS_VM_WRITE | WinAPI.PROCESS_VM_OPERATION), 0, (uint)process.Id);
            var buffer = Memory.ReadBytes(processHandle, baseAddress, (uint)process.MainModule.ModuleMemorySize);
            var rsaKey = Memory.ScanString(buffer, Constants.RealTibiaRsaHexKey);
            var loginServer = Memory.ScanString(buffer, Constants.LoginWebServiceUrl);

            process.Kill();

            if (rsaKey <= baseAddress) {
                MessageBox.Show("Unable to find rsaKey.");
                return;
            }

            if (loginServer <= baseAddress)
            {
                MessageBox.Show("Unable to find loginServer.");
                return;
            }

            var pi = new WinAPI.PROCESS_INFORMATION();
            var si = new WinAPI.STARTUPINFO();

            if (!WinAPI.CreateProcess(uxClientPath.Text, " ", IntPtr.Zero, IntPtr.Zero, false, WinAPI.CREATE_SUSPENDED, IntPtr.Zero, System.IO.Path.GetDirectoryName(uxClientPath.Text), ref si, out pi))
            {
                return;
            }

            processHandle = pi.hProcess;
            process = Process.GetProcessById(Convert.ToInt32(pi.dwProcessId));
            baseAddress = (uint)WinAPI.GetBaseAddress(processHandle).ToInt32();

            Memory.WriteString(processHandle, rsaKey + baseAddress, Constants.OpenTibiaRsaHexKey);
            Memory.WriteString(processHandle, loginServer + baseAddress, Memory.ReadString(processHandle, loginServer + baseAddress).Replace(Constants.LoginWebServiceUrl, uxIP.Text));
            WinAPI.ResumeThread(pi.hThread);
            process.WaitForInputIdle();
            WinAPI.CloseHandle(pi.hThread);

            while (process.MainWindowHandle == IntPtr.Zero)
            {
                process.Refresh();
                Thread.Sleep(5);
            }
        }
    }
}
