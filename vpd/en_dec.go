package vpd

import (
//	"fmt"
	"math"
	"io/ioutil"
	"log"
)

// ---------------------------- Types ----------------------------
type Image [][][]uint8 // H x W x 3

// ---------------------------- Byte <-> Image ----------------------------
func bytesToImage(data []byte) (Image, int) {
	origLen := len(data)
	numPixels := int(math.Ceil(float64(origLen) / 3.0))
	w := int(math.Ceil(math.Sqrt(float64(numPixels))))
	h := int(math.Ceil(float64(numPixels) / float64(w)))

	img := make(Image, h)
	idx := 0
	for i := 0; i < h; i++ {
		img[i] = make([][]uint8, w)
		for j := 0; j < w; j++ {
			pixel := []uint8{0, 0, 0}
			for c := 0; c < 3; c++ {
				if idx < origLen {
					pixel[c] = data[idx]
					idx++
				}
			}
			img[i][j] = pixel
		}
	}
	return img, origLen
}

func imageToBytes(img Image, origLen int) []byte {
	out := make([]byte, 0, origLen)
	h := len(img)
	w := len(img[0])
	idx := 0
	for i := 0; i < h && idx < origLen; i++ {
		for j := 0; j < w && idx < origLen; j++ {
			for k := 0; k < 3 && idx < origLen; k++ {
				out = append(out, img[i][j][k])
				idx++
			}
		}
	}
	return out
}

// ---------------------------- VPD (Cumulative XOR) ----------------------------
func vpdEncrypt(data []uint8) []uint8 {
	out := make([]uint8, len(data))
	copy(out, data)
	for i := 1; i < len(out); i++ {
		out[i] ^= out[i-1]
	}
	return out
}

func vpdDecrypt(data []uint8) []uint8 {
	out := make([]uint8, len(data))
	copy(out, data)
	for i := len(out) - 1; i > 0; i-- {
		out[i] ^= out[i-1]
	}
	return out
}

// ---------------------------- Bitstream ----------------------------
func convertToBitstream(img Image) []uint8 {
	h := len(img)
	w := len(img[0])
	bitstream := make([]uint8, 0, h*w*3)
	for i := 0; i < h; i++ {
		for j := 0; j < w; j++ {
			bitstream = append(bitstream, img[i][j]...)
		}
	}
	return bitstream
}

func bytesToImageFromBitstream(bitstream []uint8, h, w, origLen int) Image {
	img := make(Image, h)
	idx := 0
	byteCount := 0
	for i := 0; i < h; i++ {
		img[i] = make([][]uint8, w)
		for j := 0; j < w; j++ {
			pixel := []uint8{0, 0, 0}
			for k := 0; k < 3 && byteCount < origLen; k++ {
				pixel[k] = bitstream[idx]
				idx++
				byteCount++
			}
			img[i][j] = pixel
		}
	}
	return img
}

// ---------------------------- Intershuffling (origLen aware) ----------------------------
func intershuffling(I Image, K1, K2, K3 []uint64, origLen int) Image {
	h := len(I)
	w := len(I[0])
	d := 3
	totalBytes := origLen

	shuffled := make(Image, h)
	for i := 0; i < h; i++ {
		shuffled[i] = make([][]uint8, w)
		for j := 0; j < w; j++ {
			shuffled[i][j] = make([]uint8, 3)
			copy(shuffled[i][j], I[i][j])
		}
	}

	idx := 0
	for i := 0; i < h && idx < totalBytes; i++ {
		for j := 0; j < w && idx < totalBytes; j++ {
			for k := 0; k < d && idx < totalBytes; k++ {
				newI := int(K1[i]%256) % h
				newJ := int(K2[j]%256) % w
				newK := int(K3[k]%3) % d

				flatIdx1 := i*w*d + j*d + k
				flatIdx2 := newI*w*d + newJ*d + newK
				if flatIdx1 < totalBytes && flatIdx2 < totalBytes {
					shuffled[i][j][k], shuffled[newI][newJ][newK] = shuffled[newI][newJ][newK], shuffled[i][j][k]
				}
				idx++
			}
		}
	}
	return shuffled
}

func reverseIntershuffling(I Image, K1, K2, K3 []uint64, origLen int) Image {
	h := len(I)
	w := len(I[0])
	d := 3
	totalBytes := origLen

	reverse := make(Image, h)
	for i := 0; i < h; i++ {
		reverse[i] = make([][]uint8, w)
		for j := 0; j < w; j++ {
			reverse[i][j] = make([]uint8, 3)
			copy(reverse[i][j], I[i][j])
		}
	}

	for i := h - 1; i >= 0; i-- {
		for j := w - 1; j >= 0; j-- {
			for k := d - 1; k >= 0; k-- {
				newI := int(K1[i]%256) % h
				newJ := int(K2[j]%256) % w
				newK := int(K3[k]%3) % d

				flatIdx1 := i*w*d + j*d + k
				flatIdx2 := newI*w*d + newJ*d + newK
				if flatIdx1 < totalBytes && flatIdx2 < totalBytes {
					reverse[i][j][k], reverse[newI][newJ][newK] = reverse[newI][newJ][newK], reverse[i][j][k]
				}
			}
		}
	}
	return reverse
}

// ---------------------------- Zigzag XOR ----------------------------
func zigzagXOR(img Image, K []uint8, origLen int) Image {
	h := len(img)
	w := len(img[0])
	total := origLen
	result := make(Image, h)
	idx := 0
	for i := 0; i < h; i++ {
		result[i] = make([][]uint8, w)
		for j := 0; j < w; j++ {
			pixel := make([]uint8, 3)
			for k := 0; k < 3; k++ {
				if idx < total {
					pixel[k] = img[i][j][k] ^ K[idx%len(K)]
					idx++
				}
			}
			result[i][j] = pixel
		}
	}
	return result
}

// Zigzag XOR reversible
func reverseZigzagXOR(img Image, K []uint8, origLen int) Image {
	return zigzagXOR(img, K, origLen)
}

// ---------------------------- Planet Domain ----------------------------
func planet(I Image, K []uint8, origLen int) Image {
	return zigzagXOR(I, K, origLen)
}

func planetDec(I Image, K []uint8, origLen int) Image {
	return zigzagXOR(I, K, origLen)
}

// ---------------------------- Helpers ----------------------------
func sliceToUint64(data []uint8, length int) []uint64 {
	res := make([]uint64, length)
	for i := 0; i < length; i++ {
		res[i] = uint64(data[i%len(data)])
	}
	return res
}

// ---------------------------- Encryption ----------------------------
func Encrypt_bytes(data []byte, keys [][]uint8) []byte {
	img, origLen := bytesToImage(data)
	h := len(img)
	w := len(img[0])

	bitstream := convertToBitstream(img)
	bitstream = vpdEncrypt(bitstream)
	I1 := bytesToImageFromBitstream(bitstream, h, w, origLen)

	I2 := intershuffling(I1, sliceToUint64(keys[0], h), sliceToUint64(keys[1], w), sliceToUint64(keys[2], 3), origLen)
	I3 := zigzagXOR(I2, keys[3], origLen)

	bitstream = convertToBitstream(I3)
	bitstream = vpdEncrypt(bitstream)
	I4 := bytesToImageFromBitstream(bitstream, h, w, origLen)

	I5 := intershuffling(I4, sliceToUint64(keys[4], h), sliceToUint64(keys[5], w), sliceToUint64(keys[6], 3), origLen)
	I6 := zigzagXOR(I5, keys[3], origLen)

	bitstream = convertToBitstream(I6)
	bitstream = vpdEncrypt(bitstream)
	I7 := bytesToImageFromBitstream(bitstream, h, w, origLen)

	encrypted := planet(I7, keys[7], origLen)
	return imageToBytes(encrypted, origLen)
}

// ---------------------------- Decryption ----------------------------
func Decrypt_bytes(data []byte, keys [][]uint8) []byte {
	img, origLen := bytesToImage(data)
	h := len(img)
	w := len(img[0])

	I7 := planetDec(img, keys[7], origLen)

	bitstream := convertToBitstream(I7)
	bitstream = vpdDecrypt(bitstream)
	I6 := bytesToImageFromBitstream(bitstream, h, w, origLen)

	I5 := reverseZigzagXOR(I6, keys[3], origLen)
	I4 := reverseIntershuffling(I5, sliceToUint64(keys[4], h), sliceToUint64(keys[5], w), sliceToUint64(keys[6], 3), origLen)

	bitstream = convertToBitstream(I4)
	bitstream = vpdDecrypt(bitstream)
	I3 := bytesToImageFromBitstream(bitstream, h, w, origLen)

	I2 := reverseZigzagXOR(I3, keys[3], origLen)
	I1 := reverseIntershuffling(I2, sliceToUint64(keys[0], h), sliceToUint64(keys[1], w), sliceToUint64(keys[2], 3), origLen)

	bitstream = convertToBitstream(I1)
	bitstream = vpdDecrypt(bitstream)
	final := bytesToImageFromBitstream(bitstream, h, w, origLen)

	return imageToBytes(final, origLen)
}

func LoadKeys(filename string) [][]uint8 {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	keys := make([][]uint8, 8)
	segment := len(data) / 8
	for i := 0; i < 8; i++ {
		keys[i] = data[i*segment : (i+1)*segment]
	}
	return keys
}

// ---------------------------- Demo ----------------------------
//func main() {
	/*
	keys := make([][]uint8, 8)
	for i := 0; i < 8; i++ {
		keys[i] = make([]uint8, 1500)
		for j := 0; j < 1500; j++ {
			keys[i][j] = uint8((i + j) % 256)
		}
	}
	*/
/*
	keys := loadKeys("../project/psk/keys_seq_u8.bin")
	data := []byte("OMCI over TLS certificate authentication")
	cipher := encrypt_bytes(data, keys)
	plain := decrypt_bytes(cipher, keys)

	fmt.Println("Original :", string(data))
	fmt.Println("Cipher   :", cipher[:16], "...")
	fmt.Println("Recovered:", string(plain))
}
*/
