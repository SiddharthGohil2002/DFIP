/* SecureDelete: the file wiper in the test scenario (alice downloads and runs it). Cross-compiled with mingw-w64 by
 * make-test-image.sh, so DFIP's executable analysis has a real Windows program to read: it overwrites each file named on
 * its command line three times, renames it to AAAAAAAA.AAA and deletes it. It is test data, never run by DFIP. */
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static const char BANNER[] = "SecureDelete 1.4.0 - overwrites files before deleting them (SDWIPE/3-PASS)";
static BYTE buffer[65536];

static int wipe(const wchar_t *path)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 1;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size)) {
        CloseHandle(h);
        return 1;
    }
    static const BYTE patterns[3] = {0x00, 0xFF, 0xAA};
    for (int pass = 0; pass < 3; pass++) {
        memset(buffer, patterns[pass], sizeof buffer);
        LARGE_INTEGER start = {0};
        SetFilePointerEx(h, start, NULL, FILE_BEGIN);
        for (LONGLONG done = 0; done < size.QuadPart;) {
            DWORD chunk = (DWORD)(size.QuadPart - done < (LONGLONG)sizeof buffer ? size.QuadPart - done : sizeof buffer);
            DWORD written = 0;
            if (!WriteFile(h, buffer, chunk, &written, NULL) || written == 0)
                break;
            done += written;
        }
        FlushFileBuffers(h);
    }
    CloseHandle(h);

    /* Rename to a meaningless name in the same folder, so the journal keeps no trace of the old name's content. */
    wchar_t renamed[MAX_PATH];
    wcsncpy(renamed, path, MAX_PATH - 1);
    renamed[MAX_PATH - 1] = 0;
    wchar_t *slash = wcsrchr(renamed, L'\\');
    wchar_t *name = slash ? slash + 1 : renamed;
    if ((size_t)(name - renamed) + 13 >= MAX_PATH)
        return 1;
    wcscpy(name, L"AAAAAAAA.AAA");
    if (!MoveFileExW(path, renamed, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return 1;
    return DeleteFileW(renamed) ? 0 : 1;
}

int wmain(int argc, wchar_t **argv)
{
    puts(BANNER);
    int failed = 0;
    for (int i = 1; i < argc; i++)
        failed += wipe(argv[i]);
    return failed ? 1 : 0;
}
