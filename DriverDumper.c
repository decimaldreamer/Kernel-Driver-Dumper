#include "DriverDumper.h"
#include <stdio.h>
#include <Windows.h>

BOOL PrintKernelModules()
{
    BOOL bPrintHeader = TRUE;

    // ntdll.dll kütüphanesini belleğe yüklüyoruz. Bu kütüphane, düşük seviyeli NT API'leri içerir.
    HMODULE hNTDll = LoadLibraryW(L"ntdll.dll");
    if (!hNTDll)
    {
        // Eğer ntdll.dll yüklenemezse hata mesajı veriliyor ve işlem sonlandırılıyor.
        printf("ntdll.dll yüklenirken hata oluştu (%d)\n", GetLastError());
        return FALSE;
    }

    // "ZwQuerySystemInformation" fonksiyonunu ntdll.dll'den alıyoruz.
    ZwQuerySystemInformationType ZwQuerySystemInformation = (ZwQuerySystemInformationType)GetProcAddress(hNTDll, "ZwQuerySystemInformation");
    if (!ZwQuerySystemInformation)
    {
        // Eğer GetProcAddress başarısız olursa, hata mesajı veriliyor ve işlem sonlandırılıyor.
        printf("GetProcAddress(\"ZwQuerySystemInformation\") hatası (%d)\n", GetLastError());
        FreeLibrary(hNTDll);  // Bellekteki kütüphane serbest bırakılıyor.
        return FALSE;
    }

    // Bellek içinde tüm sistem modüllerini tutacak olan yapının pointer'ı
    SYSTEM_ALL_MODULES* pSysAllModules = NULL;
    NTSTATUS ntStatus = 0;  // NTSTATUS türünde bir değişken. Bu değişken fonksiyonların döndürdüğü hata kodlarını tutmak için kullanılır.
    DWORD dwBytesIo;  // Geri dönecek olan veri boyutunu tutmak için kullanılacak.

    // İlk çağrı, sadece gerekli bellek boyutunu öğrenmek için yapılıyor.
    ntStatus = ZwQuerySystemInformation(11, pSysAllModules, 0, &dwBytesIo);
    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH)
    {
        // Gerekli olan bellek miktarı biliniyor, bu yüzden VirtualAlloc ile bu bellek alanını tahsis ediyoruz.
        pSysAllModules = (SYSTEM_ALL_MODULES*)VirtualAlloc(NULL, dwBytesIo + 64LL, MEM_COMMIT, PAGE_READWRITE);
        if (!pSysAllModules)
        {
            // Eğer bellek tahsisi başarısız olursa, hata mesajı veriliyor ve işlem sonlandırılıyor.
            printf("VirtualAlloc hatası (%d) (%d)\n", dwBytesIo + 64LL, GetLastError());
            FreeLibrary(hNTDll);
            return FALSE;
        }

        // Belleği sıfırlıyoruz. Bu, bellek çöp verilerinin üzerine yazmamızı sağlar.
        RtlZeroMemory(pSysAllModules, dwBytesIo);

        // Şimdi gerekli bellek tahsis edildiği için gerçek modül bilgilerini alıyoruz.
        ntStatus = ZwQuerySystemInformation(11, pSysAllModules, dwBytesIo, &dwBytesIo);
        FreeLibrary(hNTDll);  // Bellekteki ntdll kütüphanesini artık serbest bırakabiliriz.

        // Eğer çağrı başarılı olduysa (ntStatus == STATUS_SUCCESS), modüller üzerinde döngü yapıyoruz.
        if (STATUS_SUCCESS == ntStatus)
        {
            for (unsigned i = 0; i < pSysAllModules->dwNumOfModules; i++)
            {
                // Modül bilgilerini alıyoruz.
                SYSTEM_MODULE_INFORMATION curMod = pSysAllModules->modules[i];
                // Modül ismini buluyoruz.
                LPSTR lpTargetModName = curMod.ImageName + curMod.ModuleNameOffset;

                // Eğer başlık bilgisi daha önce yazdırılmamışsa, yazdırıyoruz.
                if (bPrintHeader)
                {
                    printf("Driver Dumper by 0x7ff | Kullandığınız sürece keyfini çıkarın.\n");
                    printf("%-" MAX_DRIVER_NAME_LENGTH_STR "s\t%-16s\t%-16s\r\n", "Sürücü İsmi", "Base", "Size");
                    printf("%-" MAX_DRIVER_NAME_LENGTH_STR "s\t%-16s\t%-16s\r\n", "-----------", "----", "----");
                    bPrintHeader = FALSE;
                }

                // Her bir modülün adını, base adresini ve boyutunu ekrana yazdırıyoruz.
                printf("%-0" MAX_DRIVER_NAME_LENGTH_STR "s\t0x%016x\t0x%016x\r\n", lpTargetModName, curMod.Base, curMod.Size);
            }
        }

        // Bellek serbest bırakılıyor.
        VirtualFree(pSysAllModules, 0, MEM_RELEASE);
    }
    else
    {
        // Eğer beklenmedik bir NT_STATUS dönerse, hata mesajı veriliyor.
        FreeLibrary(hNTDll);
        printf("ZwQuerySystemInformation() beklenmedik NT_STATUS 0x%08x (%d)\n", ntStatus, GetLastError());
        return FALSE;
    }

    return TRUE;  // İşlem başarılı olduysa TRUE döner.
}

// Programın ana fonksiyonu
int wmain()
{
    // PrintKernelModules fonksiyonu çalıştırılıyor ve başarılı olursa çıkış değeri olarak EXIT_SUCCESS döndürülüyor, aksi halde EXIT_FAILURE.
    return PrintKernelModules() ? EXIT_SUCCESS : EXIT_FAILURE;
}
