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

	vector<byte> cipher(plain.size());
	CFB_Mode<AES>::Encryption enc;
	enc.SetKeyWithIV(key, AES::MAX_KEYLENGTH, iv, AES::BLOCKSIZE);

	ArraySink cs(&cipher[0], cipher.size());

	ArraySource(plain.data(), plain.size(), true,
		new StreamTransformationFilter(enc, new Redirector(cs)));

	return cipher;
}

vector<byte> dec(byte key[AES::MAX_KEYLENGTH], byte iv[AES::BLOCKSIZE], vector<byte> cipher) { // decrypt the cipher
	vector<byte> recover(cipher.size());
	CFB_Mode<AES>::Decryption dec;
	dec.SetKeyWithIV(key, AES::MAX_KEYLENGTH, iv, AES::BLOCKSIZE);

	ArraySink rs(&recover[0], recover.size());

	ArraySource(cipher.data(), cipher.size(), true,
		new StreamTransformationFilter(dec, new Redirector(rs)));

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
	cv::destroyWindow(name); //delete window

}

int main(int argc, char* argv[])
{

	byte key[AES::MAX_KEYLENGTH];//32
	byte iv[AES::BLOCKSIZE];//16
	RC4_Init(key);
	vector<byte> plain, cipher, recover;
	double time = 0;
	cv::Mat original, image;
	original = cv::imread("blackbuck.bmp", cv::IMREAD_UNCHANGED); //read the image
	image = original;
	showImage("opencv", original);
	plain = image2vector(image);
	Mat plainImage = vector2image(plain, image);
	showImage("plain", plainImage);
	HexEncoder encoder(new FileSink(cout));
	memset(key, 0x00, sizeof(key)); 
	memset(iv, 0x00, sizeof(iv));
	//string str("ls fixsFDSFASDFSDSSDA FDSFASDFSD END MY LIFE VALUVE pls fixs EOF");
	//std::copy(str.begin(), str.end(), std::back_inserter(plain));
	int no = plain.size() / 128;
	if (plain.size() % 128)
	{
		no = no + 1;
	}
	int j = 0;
	int t = 0;
	for (int i = 0; i < no; i++)
	{
		vector<byte> rc4K_E = RC4_keyGen(16);
		vector<byte> tempPlain;
		byte key4_E[AES::MAX_KEYLENGTH];
		memset(key4_E, 0x00, sizeof(key));
		std::copy(rc4K_E.begin(), rc4K_E.end(), key4_E); //convert key vector to array of key so that the encryption algo takes it
		for (t; t < j + 128; t++)
		{
			tempPlain.push_back(plain[t]);
		}
		j = t;
		//auto start = chrono::steady_clock::now();	//commented portion is time calculation
		vector<byte> encryption = enc(key4_E, iv, tempPlain);
		//auto end = chrono::steady_clock::now();
		//auto diff = (end - start);
		//time = time + chrono::duration <double, milli>(diff).count();
		cipher.insert(cipher.end(), encryption.begin(), encryption.end());
	}
	//cout << time << "ms\n";

	
	cipher.resize(plain.size());

	Mat cipherImage;
	cipherImage = vector2image(cipher, image);
	while (cipherImage.empty())
	{
		cipherImage = vector2image(cipher, image);
	}
	showImage("cipher", cipherImage);
	j = 0;
	t = 0;
	itRC4 = 0;
	RC4_Init(key);
	for (int i = 0; i < no; i++)
	{
		vector<byte> rc4K_D = RC4_keyGen(16);
		vector<byte> tempCipher;
		byte key4_D[AES::MAX_KEYLENGTH];
		memset(key4_D, 0x00, sizeof(key));
		cout << key4_D;
		std::copy(rc4K_D.begin(), rc4K_D.end(), key4_D);
		for (t; t < j + 128; t++)
		{
			tempCipher.push_back(cipher[t]);
		}
		j = t;
		vector<byte> decryption = dec(key4_D, iv, tempCipher);
		recover.insert(recover.end(), decryption.begin(), decryption.end());
	}
	recover.resize(plain.size());
	Mat recoverdimage;
	recoverdimage = vector2image(recover, image);
	while (recoverdimage.empty())
	{
		recoverdimage = vector2image(recover, image);
	}
	showImage("recoverd", recoverdimage);


	//cout << "PLAIN  :";
	//for (int i = 0; i < plain.size(); i++)
	//{
	//    cout << plain[i];
	//} 
	//cout << "CIPHER  :\n";
	//for (int i = 0; i < plain.size(); i++)
	//{
	//    cout << cipher[i];
	//}
	//cout << endl << recover.size() << endl;
	//cout << "Recovered texts: ";
	//for (int i = 0; i < plain.size(); i++)
	//{
	//    cout << recover[i];
	//}
	//cout << endl << "plain size: " << plain.size() << endl;
	//cout << endl << "cipher size: " << cipher.size() << endl;
	//cout << endl <<"recover size: " << recover.size() << endl;
	//cout << endl;
	return 0;
}

