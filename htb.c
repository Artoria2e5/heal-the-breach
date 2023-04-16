#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

// "64K of padding should be enough for everyone" -- William Doors
// Real talk: 64K is the maximum size of a gzip extra field
typedef uint16_t uint_pad;
typedef uint32_t uint_2pad;

#ifdef _WIN32
#include <windef.h>
#include <wincrypt.h>
#include <ya_getopt.h>
#define optarg ya_optarg
#define optind ya_optind
#define opterr ya_opterr
#define getopt ya_getopt
uint16_t htole16(uint16_t x) { return x; }
#else
#define _BSD_SOURCE
#include <endian.h>
#include <getopt.h>
#endif

bool random_2pad(uint_2pad *size) {
#ifdef _WIN32
  HCRYPTPROV provider;
  if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT)) {
    return false;
  }
  if (!CryptGenRandom(provider, sizeof(uint_2pad), (BYTE *)size)) {
    CryptReleaseContext(provider, 0);
    return false;
  }
  CryptReleaseContext(provider, 0);
#else
  FILE *urandom = fopen("/dev/urandom", "rb");
  if (urandom == NULL) {
    perror("fopen");
    return false;
  }
  setbuf(urandom, NULL);
  fread(size, sizeof(uint_2pad), 1, urandom);
  fclose(urandom);
#endif
  return true;
}

bool random_size_bounded(uint_pad *size, uint_pad max) {
  uint_2pad size_2pad = 0;
  if (!random_2pad(&size_2pad)) {
    return false;
  }
  // TODO: fix the bias (kinda kept in check by oversized source)
  *size = size_2pad % max;
  return true;
}

const char *fill_template = "htbv1";
char *htb_fill(uint_pad size) {
  char *data = malloc(size);
  // repeatedly write template
  uint_pad i = 0;
  size_t template_size = strlen(fill_template);
  while (i < size) {
    uint_pad to_write = size - i;
    if (to_write > template_size) {
      to_write = template_size;
    }
    memcpy(data + i, fill_template, to_write);
    i += to_write;
  }
  return data;
}

struct bit_banger {
  FILE *f;
  uint8_t buf;
  uint8_t buf_pos;
};

void bit_banger_init(struct bit_banger *br, FILE *f) {
  br->f = f;
  br->buf = 0;
  br->buf_pos = 0;
}

int bit_banger_read(struct bit_banger *br) {
  if (br->buf_pos == 0) {
    if (fread(&br->buf, 1, 1, br->f) != 1) {
      return EOF;
    }
    br->buf_pos = 8;
  }
  uint8_t bit = br->buf & 1;
  br->buf >>= 1;
  br->buf_pos--;
  return bit;
}

int bit_banger_read_n(struct bit_banger *br, uint8_t n) {
  uint8_t ret = 0;
  for (int i = 0; i < n; i++) {
    int bit = bit_banger_read(br);
    if (bit == EOF) {
      return EOF;
    }
    ret |= bit << i;
  }
  return ret;
}

void bit_banger_write(struct bit_banger *bw, uint8_t bit) {
  bw->buf |= bit << bw->buf_pos;
  bw->buf_pos++;
  if (bw->buf_pos == 8) {
    fwrite(&bw->buf, 1, 1, bw->f);
    bw->buf = 0;
    bw->buf_pos = 0;
  }
}

void bit_banger_write_n(struct bit_banger *bw, uint8_t n, uint8_t bits) {
  for (int i = 0; i < n; i++) {
    bit_banger_write(bw, bits & 1);
    bits >>= 1;
  }
}

bool htb_do(FILE *in, FILE *out, uint_pad maxsize) {
  uint8_t magic[4] = {0};
  if (fread(magic, 1, 4, in) != 4) {
    return false;
  }

  uint_pad padsize;
  if (!random_size_bounded(&padsize, maxsize)) {
    abort();
    return false;
  }
  char *padding = htb_fill(padsize);
  fprintf(stderr, "pad %d\n", padsize);

  if (magic[0] == 0x1f && magic[1] == 0x8b) {
    fputs("gzip\n", stderr);
    // gzip
    uint8_t flag = magic[3];
    int ch;
    // add a filename field
    magic[3] |= 0x04;
    magic[3] &= ~0x02;
    fwrite(magic, 1, 4, out);
    // copy & skip METIME, XFL, OS
    for (int i = 0; i < 6; i++) {
      ch = fgetc(in);
      fputc(ch, out);
    }
    if (flag & 0x04) {
      // copy & skip existing extra field
      uint16_t extra_len;
      fread(&extra_len, 2, 1, in);
      extra_len = htole16(extra_len);
      uint16_t extra_len_new = extra_len + 2 + 2 + padsize;
      extra_len_new = htole16(extra_len_new);
      fwrite(&extra_len_new, 2, 1, out);
      while (extra_len--) {
        ch = fgetc(in);
        fputc(ch, out);
      }
    } else {
      // add extra field
      uint16_t extra_len = 2 + 2 + padsize;
      extra_len = htole16(extra_len);
      fwrite(&extra_len, 2, 1, out);
    }
    fputc('H', out);
    fputc('T', out);
    uint16_t padsize_le = htole16(padsize);
    fwrite(&padsize_le, 2, 1, out);
    fwrite(padding, 1, padsize, out);

    if (flag & 0x08) {
      fputs("gzip name\n", stderr);
      // skip existing filename
      while ((ch = fgetc(in)) != 0) {
        fputc(ch, out);
      }
      fputc(0, out);
    }

    if (flag & 0x10) {
      fputs("gzip cmt\n", stderr);
      // skip existing comment
      while ((ch = fgetc(in)) != 0) {
        fputc(ch, out);
      }
      fputc(0, out);
    }

    // skip crc16 if present
    if (flag & 0x02) {
      fputs("gzip crc16 removed\n", stderr);
      uint16_t crc16;
      fread(&crc16, 2, 1, in);
    }

    fputs("gzip data\n", stderr);
    // copy rest of file
    while ((ch = fgetc(in)) != EOF) {
      fputc(ch, out);
    }
  } else {
    // brotli has no magic number, tough luck
    fputs("brotli?\n", stderr);
    if (padsize == 0) {
      // brotli can't handle empty meta-blocks
      padsize = 1;
      free(padding);
      padding = strdup("A");
    }
    struct bit_banger bin = {in, 0, 0};
    struct bit_banger bout = {out, 0, 0};
    // read & copy window size
    uint8_t tmp = bit_banger_read_n(&bin, 1);
    bit_banger_write_n(&bout, 1, tmp);
    if (tmp) {
      tmp = bit_banger_read_n(&bin, 3);
      bit_banger_write_n(&bout, 3, tmp);
      if (!tmp) {
        tmp = bit_banger_read_n(&bin, 3);
        bit_banger_write_n(&bout, 3, tmp);
      }
    }
    bit_banger_write_n(&bout, 5, 0b11010);
    bit_banger_write_n(&bout, 16, htole16(padsize - 1));
    // pad to byte boundary
    bit_banger_write_n(&bout, 8 - bout.buf_pos, 0);
    fwrite(padding, 1, padsize, out);
    // roll in any remaining bits in the buffer
    uint8_t n = bin.buf_pos;
    uint8_t remainder = bit_banger_read_n(&bin, bin.buf_pos);

    fputs("brotli data\n", stderr);
    assert(bin.buf_pos == 0);
    assert(bout.buf_pos == 0);

    int ch = fgetc(in);
    // bytewise copy with shift
    do {
      uint8_t tmp2 = ch >> n;
      tmp2 |= remainder;
      fputc(tmp2, out);
      remainder = ch << (8 - n);
      ch = fgetc(in);
    } while (ch != EOF);
    fputc(remainder, out);
  }
  free(padding);
  return true;
}

int main(int argc, char **argv) {
  int maxsize = 16;
  bool keep = false;
  opterr = 0;
  int c;
  while ((c = getopt(argc, argv, "km:")) != -1) {
    switch (c) {
    case 'm':
      maxsize = atoi(optarg);
      break;
    case 'k':
      keep = true;
      break;
    case '?':
      if (optopt == 'm') {
        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
      } else {
        fprintf(stderr, "Unknown option `-%c'.\n", optopt);
      }
      return 1;
    default:
      fprintf(stderr, "Usage: htb [-k] [-m maxsize] files...\n");
      return 1;
    }
  }

  if (optind == argc) {
    if (!htb_do(stdin, stdout, maxsize)) {
      perror("htb_do");
      fprintf(stderr, "Could not process stdin.\n");
      return 1;
    }
  } else {
    for (int i = optind; i < argc; i++) {
      FILE *in = fopen(argv[i], "rb");
      if (in == NULL) {
        fprintf(stderr, "Could not open %s for reading.\n", argv[i]);
        return 1;
      }
      char *tempfile = malloc(strlen(argv[i]) + 5);
      strcpy(tempfile, argv[i]);
      strcat(tempfile, ".htb");
      if (unlink(tempfile)) {
        if (errno != ENOENT) {
          perror("unlink");
          fprintf(stderr, "Could not remove %s.\n", tempfile);
          return 1;
        }
      }
      FILE *out = fopen(tempfile, "wb");
      if (out == NULL) {
        perror("fopen");
        fprintf(stderr, "Could not open %s for writing.\n", tempfile);
        return 1;
      }
      if (!htb_do(in, out, maxsize)) {
        perror("htb_do");
        fprintf(stderr, "Could not process %s.\n", argv[i]);
        return 1;
      }
      fclose(in);
      fclose(out);
      if (!keep)
        rename(tempfile, argv[i]);
    }
  }
  return 0;
}
