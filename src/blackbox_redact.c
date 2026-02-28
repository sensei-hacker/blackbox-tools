/*
 * blackbox_redact — GPS location redaction for INAV blackbox logs
 *
 * Replaces GPS_home coordinates in all binary H-frames with randomly
 * offset values. G-frames (GPS tracks) are left untouched because they
 * encode position as a delta from GPS_home (predictor=7), so their
 * decoded positions shift automatically when home changes.
 *
 * Also patches any "H waypoint[N]:lat,lon,..." text header lines if present.
 *
 * No checksums exist in the blackbox format, so in-place byte patching is safe.
 *
 * All valid lat/lon values zigzag-encode to ≤32-bit results, which fit in
 * exactly 5 variable-byte bytes. Writing a fixed 11-byte H-frame
 * (1 type byte + 5 lat bytes + 5 lon bytes) is therefore always valid
 * regardless of the original frame size.
 *
 * Usage: blackbox_redact <input.TXT> <output.TXT>
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include "parser.h"
#include "platform.h"
#include "tools.h"

/* Maximum number of binary H-frames tracked per file */
#define MAX_H_FRAMES 4096

/* Block size for bulk binary copy */
#define IO_BUF_SIZE  65536

/* Maximum text header line length */
#define MAX_LINE_LEN 4096

typedef struct {
    size_t  offset;  /* absolute byte offset from start of file */
    size_t  size;    /* frame length in bytes, including the 'H' type byte */
    int32_t lat;     /* GPS_home[0] in degrees * 1e7 */
    int32_t lon;     /* GPS_home[1] in degrees * 1e7 */
} HFrameRecord;

static HFrameRecord h_frames[MAX_H_FRAMES];
static int          h_frame_count = 0;
static size_t       binary_start_offset = SIZE_MAX; /* offset of first binary frame */

static uint8_t io_buf[IO_BUF_SIZE];

/*
 * flightLogParse callback — invoked for every decoded frame.
 * Records binary H-frame locations and the start of the binary section.
 */
static void on_frame_ready(flightLog_t *log, bool frameValid, int64_t *frame,
                           uint8_t frameType, int fieldCount,
                           int frameOffset, int frameSize)
{
    /* Track the earliest binary frame to find where text headers end */
    if (frameOffset >= 0 && (size_t)frameOffset < binary_start_offset)
        binary_start_offset = (size_t)frameOffset;

    if (frameType != 'H' || !frameValid || frame == NULL)
        return;

    if (h_frame_count >= MAX_H_FRAMES) {
        if (h_frame_count == MAX_H_FRAMES)
            fprintf(stderr, "Warning: more than %d H-frames; extras will not be redacted\n",
                    MAX_H_FRAMES);
        h_frame_count++;   /* keep counting so the warning fires only once */
        return;
    }

    int latIdx = log->gpsHomeFieldIndexes.GPS_home[0];
    int lonIdx = log->gpsHomeFieldIndexes.GPS_home[1];

    if (latIdx < 0 || lonIdx < 0 || latIdx >= fieldCount || lonIdx >= fieldCount)
        return;

    h_frames[h_frame_count].offset = (size_t)frameOffset;
    h_frames[h_frame_count].size   = (size_t)frameSize;
    h_frames[h_frame_count].lat    = (int32_t)frame[latIdx];
    h_frames[h_frame_count].lon    = (int32_t)frame[lonIdx];
    h_frame_count++;
}

/*
 * Encode an int32_t value as exactly 5 variable-byte bytes using zigzag
 * encoding. Values that normally fit in fewer bytes are padded with 0x80
 * continuation bytes (which contribute zero to the decoded result), so the
 * replacement frame always has a predictable 11-byte length.
 */
static void encode_signed_vb5(int32_t value, uint8_t out[5])
{
    uint32_t z = zigzagEncode(value);
    for (int i = 0; i < 4; i++) {
        out[i] = (uint8_t)((z & 0x7F) | 0x80);   /* continuation bit set */
        z >>= 7;
    }
    out[4] = (uint8_t)(z & 0x7F);                 /* final byte, MSB = 0 */
}

static int compare_offset(const void *a, const void *b)
{
    const HFrameRecord *fa = (const HFrameRecord *)a;
    const HFrameRecord *fb = (const HFrameRecord *)b;
    if (fa->offset < fb->offset) return -1;
    if (fa->offset > fb->offset) return  1;
    return 0;
}

/*
 * Write 'line' to 'out', patching lat/lon if it is a waypoint header.
 * Waypoint header format: "H waypoint[N]:lat,lon,..."
 */
static void process_text_line(const char *line, size_t len, FILE *out,
                              int32_t lat_offset, int32_t lon_offset)
{
    if (strncmp(line, "H waypoint[", 11) == 0) {
        int n, rest_pos;
        int32_t lat, lon;
        if (sscanf(line, "H waypoint[%d]:%d,%d%n", &n, &lat, &lon, &rest_pos) >= 3) {
            fprintf(out, "H waypoint[%d]:%d,%d%s",
                    n, lat + lat_offset, lon + lon_offset,
                    line + rest_pos);
            return;
        }
    }
    fwrite(line, 1, len, out);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input.TXT> <output.TXT>\n", argv[0]);
        return 1;
    }

    const char *input_path  = argv[1];
    const char *output_path = argv[2];

    platform_init();

    /* ------------------------------------------------------------------ *
     * Phase 1: parse to discover all binary H-frame locations             *
     * ------------------------------------------------------------------ */

    int fd = open(input_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open '%s': %s\n", input_path, strerror(errno));
        return 1;
    }

    flightLog_t *log = flightLogCreate(fd);
    if (!log) {
        fprintf(stderr, "Failed to read log header from '%s'\n", input_path);
        close(fd);
        return 1;
    }

    if (log->logCount == 0) {
        fprintf(stderr, "No flight log found in '%s'\n", input_path);
        flightLogDestroy(log);
        close(fd);
        return 1;
    }

    for (int logIndex = 0; logIndex < log->logCount; logIndex++)
        flightLogParse(log, logIndex, NULL, on_frame_ready, NULL, false);

    flightLogDestroy(log);
    close(fd);

    if (h_frame_count == 0) {
        fprintf(stderr, "No GPS home frames found — nothing to redact\n");
        return 1;
    }

    /* Cap the count at the maximum we actually stored */
    if (h_frame_count > MAX_H_FRAMES)
        h_frame_count = MAX_H_FRAMES;

    /* Sort by file offset (frames arrive in order, but be defensive) */
    qsort(h_frames, h_frame_count, sizeof(HFrameRecord), compare_offset);

    /* ------------------------------------------------------------------ *
     * Compute a random relocation offset from the first home position     *
     * ------------------------------------------------------------------ */

    srand((unsigned int)time(NULL));

    double home_lat_deg = h_frames[0].lat / 1e7;
    double home_lon_deg = h_frames[0].lon / 1e7;

    /* Clamp lat result to ±80° — avoid polar regions */
    double lat_min_deg =  -80.0 - home_lat_deg;
    double lat_max_deg =   80.0 - home_lat_deg;

    /* Keep lon offset within ±150° to avoid meridian-wrap edge cases */
    double lon_min_deg = -150.0;
    double lon_max_deg =  150.0;

    double lat_off_deg = lat_min_deg + (double)rand() / RAND_MAX * (lat_max_deg - lat_min_deg);
    double lon_off_deg = lon_min_deg + (double)rand() / RAND_MAX * (lon_max_deg - lon_min_deg);

    int32_t lat_offset = (int32_t)round(lat_off_deg * 1e7);
    int32_t lon_offset = (int32_t)round(lon_off_deg * 1e7);

    fprintf(stderr, "Original home:  lat=%11.7f  lon=%12.7f\n",
            home_lat_deg, home_lon_deg);
    fprintf(stderr, "Applied offset: lat%+11.7f  lon%+12.7f\n",
            lat_off_deg, lon_off_deg);
    fprintf(stderr, "Redacted home:  lat=%11.7f  lon=%12.7f\n",
            (h_frames[0].lat + lat_offset) / 1e7,
            (h_frames[0].lon + lon_offset) / 1e7);

    /* ------------------------------------------------------------------ *
     * Phase 2: copy file with targeted patches                            *
     * ------------------------------------------------------------------ */

    FILE *fin = fopen(input_path, "rb");
    if (!fin) {
        fprintf(stderr, "Cannot re-open '%s': %s\n", input_path, strerror(errno));
        return 1;
    }

    FILE *fout = fopen(output_path, "wb");
    if (!fout) {
        fprintf(stderr, "Cannot create '%s': %s\n", output_path, strerror(errno));
        fclose(fin);
        return 1;
    }

    /* --- 2a. Text header section: process line by line ------------------- */
    size_t text_end  = (binary_start_offset == SIZE_MAX) ? 0 : binary_start_offset;
    size_t text_pos  = 0;

    {
        char   line[MAX_LINE_LEN];
        size_t line_len = 0;
        int    c;

        while (text_pos < text_end && (c = fgetc(fin)) != EOF) {
            if (line_len < sizeof(line) - 1)
                line[line_len++] = (char)c;
            text_pos++;

            if (c == '\n' || line_len == sizeof(line) - 1) {
                line[line_len] = '\0';
                process_text_line(line, line_len, fout, lat_offset, lon_offset);
                line_len = 0;
            }
        }

        /* Flush any line not terminated by '\n' */
        if (line_len > 0) {
            line[line_len] = '\0';
            process_text_line(line, line_len, fout, lat_offset, lon_offset);
        }
    }

    /* --- 2b. Binary section: block-copy with in-place H-frame patches --- */
    size_t current_pos = text_end;

    for (int i = 0; i < h_frame_count; i++) {
        size_t h_offset = h_frames[i].offset;

        if (h_offset < current_pos) {
            fprintf(stderr,
                    "Warning: H-frame at offset %zu is behind current pos %zu — skipping\n",
                    h_offset, current_pos);
            continue;
        }

        /* Copy bytes between current_pos and the start of this H-frame */
        size_t to_copy = h_offset - current_pos;
        while (to_copy > 0) {
            size_t block = (to_copy < IO_BUF_SIZE) ? to_copy : IO_BUF_SIZE;
            size_t n = fread(io_buf, 1, block, fin);
            if (n == 0) {
                fprintf(stderr, "Unexpected EOF at offset %zu (expected H-frame at %zu)\n",
                        current_pos, h_offset);
                goto done;
            }
            fwrite(io_buf, 1, n, fout);
            current_pos += n;
            to_copy     -= n;
        }

        /* Discard the original H-frame bytes (replaced below) */
        size_t to_skip = h_frames[i].size;
        while (to_skip > 0) {
            size_t block = (to_skip < IO_BUF_SIZE) ? to_skip : IO_BUF_SIZE;
            size_t n = fread(io_buf, 1, block, fin);
            if (n == 0) break;
            to_skip -= n;
        }
        current_pos += h_frames[i].size;

        /* Write replacement 11-byte H-frame */
        uint8_t new_frame[11];
        new_frame[0] = 'H';
        encode_signed_vb5(h_frames[i].lat + lat_offset, &new_frame[1]);
        encode_signed_vb5(h_frames[i].lon + lon_offset, &new_frame[6]);
        fwrite(new_frame, 1, sizeof(new_frame), fout);
    }

    /* Copy all remaining bytes after the last H-frame */
    {
        size_t n;
        while ((n = fread(io_buf, 1, IO_BUF_SIZE, fin)) > 0)
            fwrite(io_buf, 1, n, fout);
    }

done:
    fclose(fin);
    fclose(fout);

    fprintf(stderr, "Done — %d GPS home frame(s) redacted.\n", h_frame_count);
    return 0;
}
