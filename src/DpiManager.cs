using System;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Security.Principal;

namespace TurkDPI
{
    public class DpiManager
    {
        private const string RegistryPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
        private const string DpiValue = "~ HIGHDPIAWARE";
        private const string StartupRegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        private const string AutoStartValue = "TurkDPI";

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessDPIAware();

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        private bool isQuicBlocked = false;
        private bool isPassiveDpiBlocked = false;
        private int httpFragmentationValue = 2;
        private int httpsFragmentationValue = 40;
        private bool isHostHeaderModified = false;
        private bool isTTLModified = false;

        public enum DpiMode
        {
            Legacy1, // En uyumlu mod (-p -r -s -f 2 -k 2 -n -e 2)
            Legacy2, // HTTPS için daha iyi hız (-p -r -s -f 2 -k 2 -n -e 40)
            Legacy3, // HTTP ve HTTPS için daha iyi hız (-p -r -s -e 40)
            Legacy4, // En iyi hız (-p -r -s)
            Modern1, // Kararlı mod (-f 2 -e 2 --auto-ttl --reverse-frag --max-payload)
            Modern2, // Hızlı mod (-f 2 -e 2 --wrong-seq --reverse-frag --max-payload)
            Modern3, // Güvenli mod (-f 2 -e 2 --wrong-chksum --reverse-frag --max-payload)
            Modern4, // Ultra mod (-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload)
            Modern5  // Tam koruma (-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q)
        }

        private DpiMode currentMode = DpiMode.Modern5;
        private bool isEnabled = false;

        public void EnableDpiBypass(bool blockQuic = true, bool blockPassiveDpi = true, DpiMode mode = DpiMode.Modern5)
        {
            try
            {
                currentMode = mode;
                isEnabled = true;
                SetProcessDPIAware();
                isQuicBlocked = blockQuic;
                isPassiveDpiBlocked = blockPassiveDpi;

                // DPI mod ayarlarını uygula
                ApplyDpiMode(mode);

                // Registry değişiklikleri
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(RegistryPath))
                {
                    key.SetValue(AppDomain.CurrentDomain.FriendlyName, DpiValue, RegistryValueKind.String);
                }

                // DPI bypass yöntemlerini uygula
                if (blockQuic) BlockQuicProtocol();
                if (blockPassiveDpi) EnablePassiveDpiBlocking();
                
                ModifyHostHeaders();
                ModifyTTLValue();
                OptimizeTcpStack();
                UpdateDNSSettings();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\nGelişmiş DPI Bypass başarıyla etkinleştirildi! (Mod: {mode})");
                PrintStatus();
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                throw new Exception("DPI Bypass etkinleştirilirken bir hata oluştu: " + ex.Message);
            }
        }

        private void ApplyDpiMode(DpiMode mode)
        {
            switch (mode)
            {
                case DpiMode.Legacy1:
                    httpFragmentationValue = 2;
                    httpsFragmentationValue = 2;
                    isHostHeaderModified = true;
                    isTTLModified = false;
                    break;
                case DpiMode.Legacy2:
                    httpFragmentationValue = 2;
                    httpsFragmentationValue = 40;
                    isHostHeaderModified = true;
                    isTTLModified = false;
                    break;
                case DpiMode.Legacy3:
                    httpFragmentationValue = 1;
                    httpsFragmentationValue = 40;
                    isHostHeaderModified = true;
                    isTTLModified = false;
                    break;
                case DpiMode.Legacy4:
                    httpFragmentationValue = 1;
                    httpsFragmentationValue = 1;
                    isHostHeaderModified = true;
                    isTTLModified = false;
                    break;
                case DpiMode.Modern1:
                    httpFragmentationValue = 2;
                    httpsFragmentationValue = 2;
                    isHostHeaderModified = true;
                    isTTLModified = true;
                    break;
                case DpiMode.Modern2:
                    httpFragmentationValue = 2;
                    httpsFragmentationValue = 2;
                    isHostHeaderModified = true;
                    isTTLModified = false;
                    ModifyTcpSequence();
                    break;
                case DpiMode.Modern3:
                    httpFragmentationValue = 2;
                    httpsFragmentationValue = 2;
                    isHostHeaderModified = true;
                    isTTLModified = false;
                    ModifyTcpChecksum();
                    break;
                case DpiMode.Modern4:
                    httpFragmentationValue = 2;
                    httpsFragmentationValue = 2;
                    isHostHeaderModified = true;
                    isTTLModified = false;
                    ModifyTcpSequence();
                    ModifyTcpChecksum();
                    break;
                case DpiMode.Modern5:
                    httpFragmentationValue = 2;
                    httpsFragmentationValue = 2;
                    isHostHeaderModified = true;
                    isTTLModified = false;
                    ModifyTcpSequence();
                    ModifyTcpChecksum();
                    isQuicBlocked = true;
                    break;
            }
        }

        private void ModifyTcpSequence()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                {
                    key.SetValue("TcpUseRFC1122UrgentPointer", 1, RegistryValueKind.DWord);
                    key.SetValue("EnableTcpChimney", 0, RegistryValueKind.DWord);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TCP sequence modifikasyonu sırasında hata: {ex.Message}");
            }
        }

        private void ModifyTcpChecksum()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                {
                    key.SetValue("EnableTcpChecksumOffload", 0, RegistryValueKind.DWord);
                    key.SetValue("EnableTcpTaskOffload", 0, RegistryValueKind.DWord);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TCP checksum modifikasyonu sırasında hata: {ex.Message}");
            }
        }

        private void ModifyHostHeaders()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                {
                    // Host header değişiklikleri için gerekli ayarlar
                    key.SetValue("EnableHostHeaderModification", 1, RegistryValueKind.DWord);
                    key.SetValue("HostHeaderCase", 1, RegistryValueKind.DWord);
                }
                isHostHeaderModified = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Host header modifikasyonu sırasında hata: {ex.Message}");
            }
        }

        private void ModifyTTLValue()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                {
                    // TTL değerini düşür
                    key.SetValue("DefaultTTL", 65, RegistryValueKind.DWord);
                    key.SetValue("EnableTTLModification", 1, RegistryValueKind.DWord);
                }
                isTTLModified = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TTL modifikasyonu sırasında hata: {ex.Message}");
            }
        }

        private void OptimizeTcpStack()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                {
                    // TCP optimizasyonları
                    key.SetValue("Tcp1323Opts", 1, RegistryValueKind.DWord);
                    key.SetValue("TCPNoDelay", 1, RegistryValueKind.DWord);
                    key.SetValue("TcpMaxDataRetransmissions", 3, RegistryValueKind.DWord);
                    key.SetValue("SackOpts", 1, RegistryValueKind.DWord);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TCP stack optimizasyonu sırasında hata: {ex.Message}");
            }
        }

        private void UpdateDNSSettings()
        {
            try
            {
                // Cloudflare DNS ayarları (varsayılan)
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                {
                    key.SetValue("NameServer", "1.1.1.1,1.0.0.1", RegistryValueKind.String);
                    key.SetValue("SearchList", "1.1.1.1,1.0.0.1", RegistryValueKind.String);
                }

                // DNS over HTTPS ayarları
                ConfigureDoHSettings();

                // SSL sertifika güvenliği ayarları
                ConfigureSSLSettings();

                // Network adaptör DNS ayarları
                UpdateNetworkAdapterDNS();

                Console.WriteLine("DNS ayarları Cloudflare'a göre yapılandırıldı.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DNS ayarları güncellenirken hata: {ex.Message}");
            }
        }

        private void ConfigureDoHSettings()
        {
            try
            {
                // Firefox DoH ayarları
                using (RegistryKey firefoxKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Mozilla\Firefox"))
                {
                    firefoxKey.SetValue("DNSOverHTTPS", 1, RegistryValueKind.DWord);
                    firefoxKey.SetValue("DOHProviderURL", "https://cloudflare-dns.com/dns-query", RegistryValueKind.String);
                }

                // Chrome DoH ayarları
                using (RegistryKey chromeKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Google\Chrome"))
                {
                    chromeKey.SetValue("DnsOverHttpsMode", "secure", RegistryValueKind.String);
                    chromeKey.SetValue("DnsOverHttpsTemplates", "https://cloudflare-dns.com/dns-query", RegistryValueKind.String);
                }

                // Edge DoH ayarları
                using (RegistryKey edgeKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Edge"))
                {
                    edgeKey.SetValue("DnsOverHttpsMode", "secure", RegistryValueKind.String);
                    edgeKey.SetValue("DnsOverHttpsTemplates", "https://cloudflare-dns.com/dns-query", RegistryValueKind.String);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DoH ayarları yapılandırılırken hata: {ex.Message}");
            }
        }

        private void ConfigureSSLSettings()
        {
            try
            {
                // SSL/TLS ayarları
                using (RegistryKey securityKey = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"))
                {
                    // TLS 1.2 etkinleştir
                    CreateTLSKey(securityKey, "TLS 1.2", true);
                    // TLS 1.3 etkinleştir
                    CreateTLSKey(securityKey, "TLS 1.3", true);
                }

                // Sertifika doğrulama ayarları
                using (RegistryKey certKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"))
                {
                    certKey.SetValue("VerifyServerCertificate", 0, RegistryValueKind.DWord);
                    certKey.SetValue("WarnOnBadCertRecving", 0, RegistryValueKind.DWord);
                }

                // Güvenlik protokolü ayarları
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
                ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, errors) => true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SSL ayarları yapılandırılırken hata: {ex.Message}");
            }
        }

        private void CreateTLSKey(RegistryKey parentKey, string version, bool enable)
        {
            using (RegistryKey versionKey = parentKey.CreateSubKey(version))
            using (RegistryKey clientKey = versionKey.CreateSubKey("Client"))
            using (RegistryKey serverKey = versionKey.CreateSubKey("Server"))
            {
                clientKey.SetValue("Enabled", enable ? 1 : 0, RegistryValueKind.DWord);
                clientKey.SetValue("DisabledByDefault", enable ? 0 : 1, RegistryValueKind.DWord);
                serverKey.SetValue("Enabled", enable ? 1 : 0, RegistryValueKind.DWord);
                serverKey.SetValue("DisabledByDefault", enable ? 0 : 1, RegistryValueKind.DWord);
            }
        }

        private void UpdateNetworkAdapterDNS()
        {
            try
            {
                // PowerShell komutu ile DNS ayarlarını güncelle
                string command = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Set-DnsClientServerAddress -ServerAddresses ('1.1.1.1','1.0.0.1')";
                using (System.Diagnostics.Process process = new System.Diagnostics.Process())
                {
                    process.StartInfo.FileName = "powershell.exe";
                    process.StartInfo.Arguments = $"-Command \"{command}\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Network adaptör DNS ayarları güncellenirken hata: {ex.Message}");
            }
        }

        private void BlockQuicProtocol()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                {
                    key.SetValue("EnableQuic", 0, RegistryValueKind.DWord);
                    key.SetValue("QuicAllowedPorts", "", RegistryValueKind.String);
                    key.SetValue("QuicBlocked", 1, RegistryValueKind.DWord);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"QUIC protokolü engellenirken hata: {ex.Message}");
            }
        }

        private void EnablePassiveDpiBlocking()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                {
                    // Gelişmiş DPI bypass ayarları
                    key.SetValue("EnableIPAutoConfigurationLimits", 0, RegistryValueKind.DWord);
                    key.SetValue("EnableSecurityFilters", 0, RegistryValueKind.DWord);
                    key.SetValue("EnablePMTUDiscovery", 1, RegistryValueKind.DWord);
                    key.SetValue("EnablePMTUBHDetect", 1, RegistryValueKind.DWord);
                    key.SetValue("EnableWsd", 0, RegistryValueKind.DWord);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Pasif DPI engelleme etkinleştirilirken hata: {ex.Message}");
            }
        }

        public void DisableDpiBypass()
        {
            try
            {
                if (!isEnabled)
                {
                    Console.WriteLine("DPI Bypass zaten devre dışı.");
                    return;
                }

                // Windows ağ ayarlarını sıfırla
                try
                {
                    using (var process = new System.Diagnostics.Process())
                    {
                        // Ağ ayarlarını sıfırla
                        process.StartInfo.FileName = "netsh";
                        process.StartInfo.Arguments = "winsock reset";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.CreateNoWindow = true;
                        process.Start();
                        process.WaitForExit();

                        // TCP/IP stack'i sıfırla
                        process.StartInfo.Arguments = "int ip reset";
                        process.Start();
                        process.WaitForExit();

                        // DNS önbelleğini temizle
                        process.StartInfo.Arguments = "int ip dns flush";
                        process.Start();
                        process.WaitForExit();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Windows ağ ayarları sıfırlanırken hata: {ex.Message}");
                }

                // Registry temizleme
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(RegistryPath, true))
                {
                    if (key != null)
                    {
                        try { key.DeleteValue(AppDomain.CurrentDomain.FriendlyName, false); } catch { }
                    }
                }

                // TCP/IP parametrelerini sıfırla
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", true))
                {
                    if (key != null)
                    {
                        string[] valuesToDelete = {
                            "EnableQuic", "QuicAllowedPorts", "QuicBlocked",
                            "EnableHostHeaderModification", "HostHeaderCase",
                            "DefaultTTL", "EnableTTLModification",
                            "Tcp1323Opts", "TCPNoDelay", "TcpMaxDataRetransmissions",
                            "SackOpts", "TcpUseRFC1122UrgentPointer", "EnableTcpChimney",
                            "EnableTcpChecksumOffload", "EnableTcpTaskOffload",
                            "EnableIPAutoConfigurationLimits", "EnableSecurityFilters",
                            "EnablePMTUDiscovery", "EnablePMTUBHDetect", "EnableWsd",
                            "NameServer", "SearchList"
                        };

                        foreach (string value in valuesToDelete)
                        {
                            try { key.DeleteValue(value, false); } catch { }
                        }
                    }
                }

                // Browser ayarlarını sıfırla
                string[] browserPaths = {
                    @"SOFTWARE\Policies\Mozilla\Firefox",
                    @"SOFTWARE\Policies\Google\Chrome",
                    @"SOFTWARE\Policies\Microsoft\Edge"
                };

                foreach (string path in browserPaths)
                {
                    try
                    {
                        using (RegistryKey browserKey = Registry.LocalMachine.OpenSubKey(path, true))
                        {
                            if (browserKey != null)
                            {
                                try { browserKey.DeleteValue("DNSOverHTTPS", false); } catch { }
                                try { browserKey.DeleteValue("DOHProviderURL", false); } catch { }
                                try { browserKey.DeleteValue("DnsOverHttpsMode", false); } catch { }
                                try { browserKey.DeleteValue("DnsOverHttpsTemplates", false); } catch { }
                            }
                        }
                    }
                    catch { }
                }

                // SSL/TLS ayarlarını sıfırla
                try
                {
                    using (RegistryKey securityKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols", true))
                    {
                        if (securityKey != null)
                        {
                            try { securityKey.DeleteSubKeyTree("TLS 1.2", false); } catch { }
                            try { securityKey.DeleteSubKeyTree("TLS 1.3", false); } catch { }
                        }
                    }
                }
                catch { }

                // DNS ayarlarını varsayılana döndür
                try
                {
                    using (var process = new System.Diagnostics.Process())
                    {
                        process.StartInfo.FileName = "powershell.exe";
                        process.StartInfo.Arguments = "-Command \"Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }\"";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.CreateNoWindow = true;
                        process.Start();
                        process.WaitForExit();
                    }
                }
                catch { }

                // Internet Explorer/Edge eski ayarlarını sıfırla
                try
                {
                    using (RegistryKey certKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                    {
                        if (certKey != null)
                        {
                            try { certKey.DeleteValue("VerifyServerCertificate", false); } catch { }
                            try { certKey.DeleteValue("WarnOnBadCertRecving", false); } catch { }
                        }
                    }
                }
                catch { }

                // Değişkenleri sıfırla
                isEnabled = false;
                isQuicBlocked = false;
                isPassiveDpiBlocked = false;
                isHostHeaderModified = false;
                isTTLModified = false;
                currentMode = DpiMode.Modern5;
                httpFragmentationValue = 2;
                httpsFragmentationValue = 40;

                // Windows servislerini yeniden başlat
                try
                {
                    using (var process = new System.Diagnostics.Process())
                    {
                        process.StartInfo.FileName = "cmd.exe";
                        process.StartInfo.Arguments = "/c net stop dnscache && net start dnscache";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.CreateNoWindow = true;
                        process.Start();
                        process.WaitForExit();
                    }
                }
                catch { }
                
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\nDPI Bypass başarıyla devre dışı bırakıldı.");
                Console.WriteLine("Tüm ağ ayarları varsayılan değerlerine döndürüldü.");
                Console.WriteLine("Değişikliklerin tam olarak uygulanması için bilgisayarınızı yeniden başlatmanız GEREKLİDİR.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                throw new Exception("DPI Bypass devre dışı bırakılırken bir hata oluştu: " + ex.Message);
            }
        }

        private void PrintStatus()
        {
            Console.WriteLine($"DPI Modu: {currentMode}");
            Console.WriteLine($"QUIC Engelleme: {(isQuicBlocked ? "Aktif" : "Pasif")}");
            Console.WriteLine($"Pasif DPI Engelleme: {(isPassiveDpiBlocked ? "Aktif" : "Pasif")}");
            Console.WriteLine($"Host Header Modifikasyonu: {(isHostHeaderModified ? "Aktif" : "Pasif")}");
            Console.WriteLine($"TTL Modifikasyonu: {(isTTLModified ? "Aktif" : "Pasif")}");
            Console.WriteLine($"HTTP Fragmentasyon: {httpFragmentationValue}");
            Console.WriteLine($"HTTPS Fragmentasyon: {httpsFragmentationValue}");
        }

        public void CheckDpiStatus()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(RegistryPath))
                {
                    var value = key?.GetValue(AppDomain.CurrentDomain.FriendlyName);
                    bool isActive = value != null && value.ToString().Contains("HIGHDPIAWARE");

                    Console.ForegroundColor = isActive ? ConsoleColor.Green : ConsoleColor.Yellow;
                    Console.WriteLine($"\nDPI Bypass Durumu: {(isActive ? "Etkin" : "Devre Dışı")}");
                    
                    if (isActive)
                    {
                        PrintStatus();
                    }
                    
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("DPI durumu kontrol edilirken bir hata oluştu: " + ex.Message);
            }
        }

        public void SetFragmentationValues(int httpValue, int httpsValue)
        {
            httpFragmentationValue = httpValue;
            httpsFragmentationValue = httpsValue;
            Console.WriteLine($"Fragmentasyon değerleri güncellendi: HTTP={httpValue}, HTTPS={httpsValue}");
        }

        public bool IsAutoStartEnabled()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(StartupRegistryPath))
                {
                    return key?.GetValue(AutoStartValue) != null;
                }
            }
            catch
            {
                return false;
            }
        }

        public void SetAutoStart(bool enable)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(StartupRegistryPath))
                {
                    if (enable)
                    {
                        string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                        key.SetValue(AutoStartValue, $"\"{exePath}\" --autostart", RegistryValueKind.String);
                        Console.WriteLine("DPI Bypass otomatik başlatma etkinleştirildi.");
                    }
                    else
                    {
                        key.DeleteValue(AutoStartValue, false);
                        Console.WriteLine("DPI Bypass otomatik başlatma devre dışı bırakıldı.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Otomatik başlatma ayarı değiştirilirken hata: {ex.Message}");
            }
        }

        public bool IsDpiBypassEnabled()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(RegistryPath))
                {
                    var value = key?.GetValue(AppDomain.CurrentDomain.FriendlyName);
                    return value != null && value.ToString().Contains("HIGHDPIAWARE");
                }
            }
            catch
            {
                return false;
            }
        }
    }
} 