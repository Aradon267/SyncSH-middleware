#include "Helper.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

using std::string;

// recieves the type code of the message from socket (1 byte)
// and returns the code. if no message found in the socket returns 0 (which means the client disconnected)
int Helper::getMessageTypeCode(SOCKET sc)
{
	char* s = getPartFromSocket(sc, 1);
	std::string msg(s);

	if (msg == "")
		return 0;
	// int res = std::atoi(s);
	int res = (int) s[0];
	delete s;
	return  res;
}

// recieve data from socket according byteSize
// returns the data as int
int Helper::getIntPartFromSocket(SOCKET sc, int bytesNum)
{
	char* s = getPartFromSocket(sc, bytesNum, 0);
	return atoi(s);
}

// recieve data from socket according byteSize
// returns the data as string
string Helper::getStringPartFromSocket(SOCKET sc, int bytesNum)
{
	char* s = getPartFromSocket(sc, bytesNum, 0);
	string complete;
	for (int i = 0; i < bytesNum; i++) {
		if (s[i] != -51) {
			complete = complete + s[i];
		}
	}
	return complete;
}

// return string after padding zeros if necessary
string Helper::getPaddedNumber(int num, int digits)
{
	std::ostringstream ostr;
	ostr << std::setw(digits) << std::setfill('0') << num;
	return ostr.str();

}

// recieve data from socket according byteSize
// this is private function
char* Helper::getPartFromSocket(SOCKET sc, int bytesNum)
{
	return getPartFromSocket(sc, bytesNum, 0);
}

char* Helper::getPartFromSocket(SOCKET sc, int bytesNum, int flags)
{
	if (bytesNum == 0)
	{
		return (char*)"";
	}

	char* data = new char[bytesNum + 1];
	int res = recv(sc, data, bytesNum, flags);

	if (res == INVALID_SOCKET)
	{
		std::string s = "Error while recieving from socket: ";
		s += std::to_string(sc);
		throw std::exception(s.c_str());
	}

	data[bytesNum] = 0;
	return data;
}

// send data to socket
// this is private function
void Helper::sendData(SOCKET sc, std::string message)
{
	const char* data = message.c_str();

	if (send(sc, data, message.size(), 0) == INVALID_SOCKET)
	{
		throw std::exception("Error while sending message to client");
	}
}

string Helper::getDateNow()
{
	time_t now = time(nullptr);
	std::stringstream oss;
	oss << std::put_time(localtime(&now), "%d/%m/%Y %H:%M:%S");
	return oss.str();
}

int Helper::getJsonSize(SOCKET sc)
{
	char* s = getPartFromSocket(sc, 4);
	//<< means left * (2^right) we sent the size like this from the client
	unsigned int res = unsigned int((unsigned char)(s[0]) << 24 |
		(unsigned char)(s[1]) << 16 |
		(unsigned char)(s[2]) << 8 |
		(unsigned char)(s[3]) & 0xFF);

	return  res;
}

void Helper::trim(std::string& str)
{
	size_t startpos = str.find_first_not_of(" \t");
	if (std::string::npos != startpos)
	{
		str = str.substr(startpos);
	}
}
