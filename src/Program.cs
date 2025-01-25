using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Net;
using System.IO;
using System.Collections.Generic;

namespace TurkDPI
{
    class Program
    {
        private static Dictionary<string, string> settings = new Dictionary<string, string>();

        static void Main(string[] args)
        {
            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Bu uygulama yönetici hakları gerektirir!");
                Console.WriteLine("Lütfen uygulamayı yönetici olarak çalıştırın.");
                Console.ResetColor();
                Console.WriteLine("\nDevam etmek için bir tuşa basın...");
                Console.ReadKey();
                return;
            }

            LoadSettings();
            var dpiManager = new DpiManager();

            // Otomatik başlatma kontrolü
            if (args.Length > 0 && args[0] == "--autostart")
            {
                if (dpiManager.IsDpiBypassEnabled())
                {
                    return;
                }
                else
                {
                    ApplySettingsFromFile(dpiManager);
                    return;
                }
            }

            Console.Title = "TürkDPI - Gelişmiş DPI Bypass Aracı";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔════════════════════════════════════╗");
            Console.WriteLine("║           TürkDPI v1.0.0          ║");
            Console.WriteLine("║    Gelişmiş DPI Bypass Aracı      ║");
            Console.WriteLine("╚════════════════════════════════════╝\n");
            Console.ResetColor();

            try
            {
                while (true)
                {
                    Console.WriteLine("\n[1] DPI Bypass'ı Etkinleştir (settings.txt'den)");
                    Console.WriteLine("[2] DPI Bypass'ı Etkinleştir (Gelişmiş Ayarlar)");
                    Console.WriteLine("[3] DPI Bypass'ı Devre Dışı Bırak");
                    Console.WriteLine("[4] Mevcut DPI Durumunu Kontrol Et");
                    Console.WriteLine("[5] Fragmentasyon Değerlerini Ayarla");
                    Console.WriteLine("[6] DNS Ayarlarını Yapılandır");
                    Console.WriteLine("[7] Otomatik Başlatma Ayarları");
                    Console.WriteLine("[8] Çıkış");

                    Console.Write("\nSeçiminiz (1-8): ");
                    string choice = Console.ReadLine();

                    switch (choice)
                    {
                        case "1":
                            ApplySettingsFromFile(dpiManager);
                            break;
                        case "2":
                            ConfigureAdvancedSettings(dpiManager);
                            break;
                        case "3":
                            dpiManager.DisableDpiBypass();
                            break;
                        case "4":
                            dpiManager.CheckDpiStatus();
                            break;
                        case "5":
                            ConfigureFragmentationValues(dpiManager);
                            break;
                        case "6":
                            ConfigureDNSSettings(dpiManager);
                            break;
                        case "7":
                            ConfigureAutoStart(dpiManager);
                            break;
                        case "8":
                            Environment.Exit(0);
                            break;
                        default:
                            Console.WriteLine("Geçersiz seçim! Lütfen 1-8 arası bir değer girin.");
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\nHata: {ex.Message}");
                Console.ResetColor();
                Console.WriteLine("\nDevam etmek için bir tuşa basın...");
                Console.ReadKey();
            }
        }

        private static void LoadSettings()
        {
            try
            {
                string settingsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "settings.txt");
                if (!File.Exists(settingsPath))
                {
                    Console.WriteLine("settings.txt dosyası bulunamadı! Varsayılan ayarlar kullanılacak.");
                    return;
                }

                foreach (string line in File.ReadAllLines(settingsPath))
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    string[] parts = line.Split('=');
                    if (parts.Length == 2)
                    {
                        settings[parts[0].Trim()] = parts[1].Trim();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ayar dosyası okunurken hata oluştu: {ex.Message}");
            }
        }

        private static void ApplySettingsFromFile(DpiManager dpiManager)
        {
            try
            {
                // DPI Modu
                int dpiMode = GetSettingInt("DPI_MODE", 8);
                bool blockQuic = GetSettingBool("BLOCK_QUIC", true);
                bool blockPassiveDpi = GetSettingBool("BLOCK_PASSIVE_DPI", true);

                // Fragmentasyon değerleri
                int httpFrag = GetSettingInt("HTTP_FRAGMENTATION", 2);
                int httpsFrag = GetSettingInt("HTTPS_FRAGMENTATION", 40);

                // DNS ayarları
                int dnsProvider = GetSettingInt("DNS_PROVIDER", 1);
                string dnsPrimary = GetSetting("DNS_PRIMARY", "1.1.1.1");
                string dnsSecondary = GetSetting("DNS_SECONDARY", "1.0.0.1");

                // Diğer ayarlar
                bool autoStart = GetSettingBool("AUTO_START", false);
                bool modifyHostHeaders = GetSettingBool("MODIFY_HOST_HEADERS", true);
                bool modifyTtl = GetSettingBool("MODIFY_TTL", true);
                bool optimizeTcp = GetSettingBool("OPTIMIZE_TCP", true);
                bool enableSslOpt = GetSettingBool("ENABLE_SSL_OPTIMIZATION", true);

                // Ayarları uygula
                dpiManager.EnableDpiBypass(blockQuic, blockPassiveDpi, (DpiManager.DpiMode)dpiMode);
                dpiManager.SetFragmentationValues(httpFrag, httpsFrag);
                dpiManager.SetAutoStart(autoStart);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\nAyarlar başarıyla uygulandı!");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ayarlar uygulanırken hata oluştu: {ex.Message}");
            }
        }

        private static string GetSetting(string key, string defaultValue)
        {
            return settings.ContainsKey(key) ? settings[key] : defaultValue;
        }

        private static bool GetSettingBool(string key, bool defaultValue)
        {
            if (settings.ContainsKey(key))
            {
                return settings[key].ToLower() == "true";
            }
            return defaultValue;
        }

        private static int GetSettingInt(string key, int defaultValue)
        {
            if (settings.ContainsKey(key) && int.TryParse(settings[key], out int value))
            {
                return value;
            }
            return defaultValue;
        }

        private static bool IsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void ConfigureAdvancedSettings(DpiManager dpiManager)
        {
            Console.WriteLine("\n--- Gelişmiş Ayarlar ---");
            
            Console.WriteLine("\nDPI Bypass Modları:");
            Console.WriteLine("1. Legacy Mod 1 - En uyumlu mod (Türkiye için önerilen)");
            Console.WriteLine("2. Legacy Mod 2 - HTTPS için daha iyi hız");
            Console.WriteLine("3. Legacy Mod 3 - HTTP ve HTTPS için daha iyi hız");
            Console.WriteLine("4. Legacy Mod 4 - En iyi hız");
            Console.WriteLine("5. Modern Mod 1 - Kararlı mod");
            Console.WriteLine("6. Modern Mod 2 - Hızlı mod");
            Console.WriteLine("7. Modern Mod 3 - Güvenli mod");
            Console.WriteLine("8. Modern Mod 4 - Ultra mod");
            Console.WriteLine("9. Modern Mod 5 - Tam koruma (Varsayılan)");

            Console.Write("\nMod seçiminiz (1-9): ");
            if (int.TryParse(Console.ReadLine(), out int modeChoice) && modeChoice >= 1 && modeChoice <= 9)
            {
                DpiManager.DpiMode selectedMode = (DpiManager.DpiMode)(modeChoice - 1);

                Console.Write("\nQUIC Protokolünü Engelle (E/H): ");
                bool blockQuic = Console.ReadLine().Trim().ToUpper().StartsWith("E");

                Console.Write("Pasif DPI Engellemesini Etkinleştir (E/H): ");
                bool blockPassiveDpi = Console.ReadLine().Trim().ToUpper().StartsWith("E");

                dpiManager.EnableDpiBypass(blockQuic, blockPassiveDpi, selectedMode);
            }
            else
            {
                Console.WriteLine("Geçersiz mod seçimi! Varsayılan mod (Modern 5) kullanılacak.");
                dpiManager.EnableDpiBypass();
            }
        }

        private static void ConfigureFragmentationValues(DpiManager dpiManager)
        {
            Console.WriteLine("\n--- Fragmentasyon Ayarları ---");
            
            Console.Write("HTTP Fragmentasyon Değeri (2-6): ");
            if (int.TryParse(Console.ReadLine(), out int httpValue) && httpValue >= 2 && httpValue <= 6)
            {
                Console.Write("HTTPS Fragmentasyon Değeri (40-120): ");
                if (int.TryParse(Console.ReadLine(), out int httpsValue) && httpsValue >= 40 && httpsValue <= 120)
                {
                    dpiManager.SetFragmentationValues(httpValue, httpsValue);
                    Console.WriteLine("Fragmentasyon değerleri başarıyla güncellendi!");
                    return;
                }
            }
            
            Console.WriteLine("Geçersiz değer! Varsayılan değerler kullanılacak.");
        }

        private static void ConfigureDNSSettings(DpiManager dpiManager)
        {
            Console.WriteLine("\n--- DNS Ayarları ---");
            Console.WriteLine("1. Cloudflare DNS (1.1.1.1, 1.0.0.1) [Önerilen]");
            Console.WriteLine("2. Google DNS (8.8.8.8, 8.8.4.4)");
            Console.WriteLine("3. OpenDNS (208.67.222.222, 208.67.220.220)");
            Console.WriteLine("4. Özel DNS");

            Console.Write("\nSeçiminiz (1-4): ");
            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    using (var process = new System.Diagnostics.Process())
                    {
                        process.StartInfo.FileName = "powershell.exe";
                        process.StartInfo.Arguments = "-Command \"Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).InterfaceIndex -ServerAddresses ('1.1.1.1','1.0.0.1')\"";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.CreateNoWindow = true;
                        process.Start();
                        process.WaitForExit();
                    }
                    Console.WriteLine("Cloudflare DNS ayarları başarıyla uygulandı.");
                    break;
                case "2":
                    using (var process = new System.Diagnostics.Process())
                    {
                        process.StartInfo.FileName = "powershell.exe";
                        process.StartInfo.Arguments = "-Command \"Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).InterfaceIndex -ServerAddresses ('8.8.8.8','8.8.4.4')\"";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.CreateNoWindow = true;
                        process.Start();
                        process.WaitForExit();
                    }
                    Console.WriteLine("Google DNS ayarları başarıyla uygulandı.");
                    break;
                case "3":
                    using (var process = new System.Diagnostics.Process())
                    {
                        process.StartInfo.FileName = "powershell.exe";
                        process.StartInfo.Arguments = "-Command \"Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).InterfaceIndex -ServerAddresses ('208.67.222.222','208.67.220.220')\"";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.CreateNoWindow = true;
                        process.Start();
                        process.WaitForExit();
                    }
                    Console.WriteLine("OpenDNS ayarları başarıyla uygulandı.");
                    break;
                case "4":
                    Console.Write("Birincil DNS: ");
                    string primaryDns = Console.ReadLine();
                    Console.Write("İkincil DNS: ");
                    string secondaryDns = Console.ReadLine();
                    
                    if (IPAddress.TryParse(primaryDns, out _) && IPAddress.TryParse(secondaryDns, out _))
                    {
                        using (var process = new System.Diagnostics.Process())
                        {
                            process.StartInfo.FileName = "powershell.exe";
                            process.StartInfo.Arguments = $"-Command \"Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {{$_.Status -eq 'Up'}}).InterfaceIndex -ServerAddresses ('{primaryDns}','{secondaryDns}')\"";
                            process.StartInfo.UseShellExecute = false;
                            process.StartInfo.RedirectStandardOutput = true;
                            process.StartInfo.CreateNoWindow = true;
                            process.Start();
                            process.WaitForExit();
                        }
                        Console.WriteLine("Özel DNS ayarları başarıyla uygulandı.");
                    }
                    else
                    {
                        Console.WriteLine("Geçersiz IP adresi! Varsayılan DNS ayarları kullanılacak.");
                    }
                    break;
                default:
                    Console.WriteLine("Geçersiz seçim! Cloudflare DNS ayarları kullanılacak.");
                    using (var process = new System.Diagnostics.Process())
                    {
                        process.StartInfo.FileName = "powershell.exe";
                        process.StartInfo.Arguments = "-Command \"Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).InterfaceIndex -ServerAddresses ('1.1.1.1','1.0.0.1')\"";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.CreateNoWindow = true;
                        process.Start();
                        process.WaitForExit();
                    }
                    break;
            }
        }

        private static void ConfigureAutoStart(DpiManager dpiManager)
        {
            Console.WriteLine("\n--- Otomatik Başlatma Ayarları ---");
            Console.WriteLine($"Mevcut Durum: {(dpiManager.IsAutoStartEnabled() ? "Etkin" : "Devre Dışı")}");
            Console.Write("\nOtomatik başlatmayı etkinleştirmek istiyor musunuz? (E/H): ");
            
            bool enable = Console.ReadLine().Trim().ToUpper().StartsWith("E");
            dpiManager.SetAutoStart(enable);
        }
    }
} 