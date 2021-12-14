//Created by Samir Abuisneneh
//Encrypting an image using AES_CBC mode and RC4 random key generation 
#include "files.h"
#include "osrng.h"
#include "cryptlib.h"
#include "filters.h"
#include "modes.h"
#include "hex.h"
#include "aes.h"
#include <vector>
#include <cmath>
#include <iostream>
#include <string>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/core.hpp>
#include<chrono>

using namespace std;
using namespace cv;
using namespace CryptoPP;

vector<byte> S(256);
vector<byte> T(256);
int itRC4 = 0;

void RC4_Init(byte key[]) // to initialize the RC4 table
{
	for (int i = 0; i <= 255; i++)
	{
		S[i] = i;
		T[i] = key[i % AES::MAX_KEYLENGTH];
	}

	int temp = 0;
	for (int i = 0; i <= 255; i++)
	{
		temp = (temp + S[i] + T[i]) % 256;
		swap(S[i], S[temp]);
	}
}

vector<byte> RC4_keyGen(int num) { // generate a specified number of bytes
	int i = 0;
	int j = 0;
	int t;
	vector<byte> val;
	for (int k = itRC4; k < itRC4 + num; k++)
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		swap(S[i], S[j]);
		t = (S[i] + S[j]) % 256;
		val.push_back(S[t]);
	}
	itRC4 = num;
	return val;
}

vector<byte> enc(byte key[AES::MAX_KEYLENGTH], byte iv[AES::BLOCKSIZE], vector<byte> plain) { //encrypt the plain text

	vector<byte> cipher(plain.size()+16); //because cipher adds a padding block
	CBC_Mode<AES>::Encryption enc;
	enc.SetKeyWithIV(key, AES::MAX_KEYLENGTH, iv, AES::BLOCKSIZE);

	ArraySink cs(&cipher[0], cipher.size());

	ArraySource(plain.data(), plain.size(), true,
		new StreamTransformationFilter(enc, new Redirector(cs))); //Set cipher text length now that its known
	cipher.resize(cs.TotalPutLength());
	return cipher;
}

vector<byte> dec(byte key[AES::MAX_KEYLENGTH], byte iv[AES::BLOCKSIZE], vector<byte> cipher) { // decrypt the cipher
	vector<byte> recover(cipher.size()); //Recovered text will be less than cipher text
	CBC_Mode<AES>::Decryption dec;
	dec.SetKeyWithIV(key, AES::MAX_KEYLENGTH, iv, AES::BLOCKSIZE);

	ArraySink rs(&recover[0], recover.size());

	ArraySource(cipher.data(), cipher.size(), true,
		new StreamTransformationFilter(dec, new Redirector(rs)));
	recover.resize(rs.TotalPutLength()); //Set recovered text length now that its known
	return recover;
}

vector<byte> image2vector(Mat image) { //convert image (Mat) to vector of Bytes
	byte totalElements = image.total() * image.channels(); // Note: image.total() == rows*cols., for our case 512*512*3
	cv::Mat flat = image.reshape(1, totalElements); // 1xN mat of 1 channel

	// Converting to vector
	std::vector<byte> vec(flat.data, flat.data + flat.total()); 
	return vec;
}

Mat vector2image(vector<byte> vec, Mat image) {
	Mat Restored = cv::Mat(image.rows, image.cols, image.type(), vec.data()); //restore vector into image
	return Restored;
}

void showImage(string name, Mat image) {

	cv::namedWindow(name, cv::WINDOW_AUTOSIZE);//create display window
	cv::imshow(name, image); //show the cipher image
	cv::waitKey(0); //wait for user input

}

void printAll(vector<byte> plain, vector<byte> cipher, vector<byte> recover) {
	cout << "plain  :";
	for (int i = 0; i < plain.size(); i++)
	{
		cout << plain[i];
	}
	cout << "\ncipher  :\n";
	for (int i = 0; i < plain.size(); i++)
	{
		cout << cipher[i];
	}
	cout << endl << recover.size() << endl;
	cout << "recovered texts: ";
	for (int i = 0; i < plain.size(); i++)
	{
		cout << recover[i];
	}
	cout << endl << "plain size: " << plain.size() << endl;
	cout << endl << "cipher size: " << cipher.size() << endl;
	cout << endl << "recover size: " << recover.size() << endl;
}

void calculateTime(Mat image, double time_ms) { // calculate the ET and the number of cycles per Byte
	double CPU_speed = 3.6 * pow(10, 9);// depends on machine
	double ET = image.total()*image.channels() / (time_ms * pow(10, -3));//image.total()*imgae.channels = col*row*3
	double numOfCycles = CPU_speed / ET;
	cout << "Time: " << time_ms << endl;//time of execution
	cout << "Encryption Throughput: " << ET << endl;// encryption throughput
	cout << "Number of cycles per Byte : " << numOfCycles << endl;// number of cycles per Byte
}

int main(int argc, char* argv[])
{
	//declartions
	byte key[AES::MAX_KEYLENGTH];//32
	byte iv[AES::BLOCKSIZE];//16
	memset(key, 0x00, sizeof(key));
	memset(iv, 0x00, sizeof(iv));
	HexEncoder encoder(new FileSink(cout));
	RC4_Init(key);
	vector<byte> plain, cipher, recover;
	double time = 0;
	cv::Mat original, image;

	//image to plain text
	original = cv::imread("blackbuck.bmp", cv::IMREAD_UNCHANGED); //read the image
	image = original;
	showImage("plain", original);
	plain = image2vector(image);
	Mat plainImage = vector2image(plain, image);
	showImage("plain", plainImage);
	
	//string str("ls fixsFDSFASDFSDSSDA  GFDG FD GFDGFDGFD GF HGFHGF HGFTYT g  GFDG FDGFDGFDGFDG DFG FD GFD G FDG FDG FDG FD GFD GFD GFD GFD GFD GFD G RGRE TRE TREL TLRE TLRE LTREL TL REL TR{E TLR{E LT{RE LT{RE LT{R ELT{ REL{ LG{FDLG{R LGE{L F{DGL{R ELG{ LD{G LR{E LG{R LG{DL{R GLD{ LG{FLD {GRL D{GLFD{ GLR{L G{FDLG{ RLD{GL F{DL G{RLD {GL{FDL G{RLD{GL {FLD{ GLR{ LG{RDL{FGLR{DL{GLF{DLGR{LDG{FLGR{DLF{GL{RDL{GFL{DLGR{LDG{FDL{GLF{DFDGFDG GFDGDFGDFDFGGDFDFG GFDGGDFGFDGDFGDFGDF GRTR RGHGF HGF HGF HGF HGF HGF H TRE TREW TRE GFDSGFD SGFD SGF GFDS GFDS GFD SGDFGFDSGFDGfdE RG GE GRE GR EGR EG RE GRE GREGFDFGDGFD GRE GREG RE GRE GFDG FDGFDG RE GR GFD GREFGD RRTY GHHGHGFHG HD GFDGFDG FfdsY LIFE VALUVE GFDGFDG F DGFDGRTRE TRE TR ET RE TRE GFDG FD pls fixs EOF");
	//std::copy(str.begin(), str.end(), std::back_inserter(plain));
	int no = plain.size() / 128;
	if (plain.size() % 128)
	{
		no = no + 1;
	}
	int j = 0;
	int t = 0;
	byte newIV[AES::BLOCKSIZE];
	for (int i = 0; i < size(iv); i++)
	{
		newIV[i] = iv[i];
	}
	for (int i = 0; i < no; i++) //no is the number of iterations (blocks)
	{
		vector<byte> tempPlain;
		vector<byte> rc4K_E = RC4_keyGen(16); // start of key gen
		byte key4_E[AES::MAX_KEYLENGTH];
		memset(key4_E, 0x00, sizeof(key));
		std::copy(rc4K_E.begin(), rc4K_E.end(), key4_E); //end of key gen
		for (t; t < j + 128; t++)
		{
			tempPlain.push_back(plain[t]); //get block from plain
		}
		j = t;
		auto start = chrono::steady_clock::now();	//commented portion is time calculation
		vector<byte> encryption = enc(key4_E, newIV, tempPlain);//encryption of block
		auto end = chrono::steady_clock::now();
		auto diff = (end - start);
		time = time + chrono::duration <double, milli>(diff).count();
		for (int i = 113; i <= 128; i++) // new iv where iv is the cipher text
		{
			newIV[i-113] = encryption[i];
		}
		cipher.insert(cipher.end(), encryption.begin(), encryption.end()); // insert into cipher
	}
	
	//cipher.resize(plain.size());
	vector<byte> man(cipher.size());
	for (int i = 0; i < cipher.size(); i++)
	{
		man[i] = cipher[i];
	}
	Mat cipherImage;
	cipherImage = vector2image(cipher, image);
	showImage("cipher", cipherImage);
	j = 0;
	t = 0;
	itRC4 = 0;
	RC4_Init(key);
	for (int i = 0; i < size(iv); i++)
	{
		newIV[i] = iv[i];
	}
	for (int i = 0; i < no; i++)
	{
		vector<byte> rc4K_D = RC4_keyGen(16);//start of key gen
		vector<byte> tempCipher;
		byte key4_D[AES::MAX_KEYLENGTH];
		memset(key4_D, 0x00, sizeof(key));
		cout << key4_D;
		std::copy(rc4K_D.begin(), rc4K_D.end(), key4_D);//end of key gen
		for (t; t < j + 128+16; t++)
		{
			tempCipher.push_back(cipher[t]); //get a cipher block
		}
		j = t;
		vector<byte> decryption = dec(key4_D, newIV, tempCipher);//decrypt the block
		for (int i = 113; i <= 128; i++)//new iv where iv is the cipher text

		{
			newIV[i - 113] = tempCipher[i];
		}
		recover.insert(recover.end(), decryption.begin(), decryption.end());//insert recoverd data into recover
	}
	recover.resize(plain.size()); // resize the recover to match the plain
	Mat recoverdimage;
	recoverdimage = vector2image(recover, image);
	showImage("recoverd", recoverdimage); //display recoverd image
	calculateTime(image, time);
	//printAll(plain, cipher, recover);
	return 0;
}

