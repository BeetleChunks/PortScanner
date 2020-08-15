#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define SCAN_DEFAULT_TIMEOUT 2

#pragma comment (lib, "Ws2_32.lib")

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>

VOID PrintUsage();
VOID ReplaceAll(std::wstring& str, std::wstring& from, std::wstring& to);
BOOL ResultsToCSV(std::vector <std::map<std::wstring, std::wstring>>& vMapResults, std::wstring& csvFilePath);
BOOL IsTcpPortOpen(std::wstring host, std::wstring port, long timeoutSecs);
VOID StartScanning(std::vector <std::wstring> vwsArgs);

int wmain(int argc, wchar_t** argv) {
	std::vector <std::wstring> vwsArgs;

	int i = 1;
	while (i < argc) {
		vwsArgs.push_back(argv[i]);
		i++;
	}

	StartScanning(vwsArgs);

	return 0;
}

VOID PrintUsage() {
	std::wcout << L"Usage: LocalGroupMembers.exe [options] --csv <out file>" << std::endl;
	std::wcout << L"-h\tPrint this usage screen" << std::endl;
	std::wcout << L"-t\tTarget host for scanning" << std::endl;
	std::wcout << L"-tL\tFile of line delimited target hosts for scanning" << std::endl;
	std::wcout << L"-p\tPorts to scan (comma separated)" << std::endl;
	std::wcout << L"-v\tDisplay closed connections" << std::endl;
	std::wcout << L"--timeout\tConnection timeout in seconds (Default is 2)" << std::endl;
	std::wcout << L"--csv\tCSV file path to store results" << std::endl;
}

VOID ReplaceAll(std::wstring& str, std::wstring& from, std::wstring& to) {
	if (from.empty())
		return;

	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
}

BOOL ResultsToCSV(std::vector <std::map<std::wstring, std::wstring>>& vMapResults, std::wstring& csvFilePath) {
	std::vector <std::wstring> vColumns;
	UINT i = 0;
	UINT j = 0;

	// Open target csv file for writing
	std::wofstream csvFile;
	csvFile.open(csvFilePath);

	// Create column keys from all result keys
	i = 0;
	while (i < vMapResults.size()) {
		for (auto it = vMapResults[i].cbegin(); it != vMapResults[i].cend(); ++it) {
			vColumns.push_back((*it).first);
		}

		// Unique vector here. Idea is to keep memory down
		std::sort(vColumns.begin(), vColumns.end());
		vColumns.erase(std::unique(vColumns.begin(), vColumns.end()), vColumns.end());

		i++;
	}

	// Create/Write column row
	std::wstring columnLine;

	i = 0;
	while (i < vColumns.size() - 1) {
		std::wstring value = vColumns[i];

		// Wrap in double quotes if value contains a comma
		if (value.find(L',') != std::wstring::npos) {
			// RFC-4180, paragraph 7. "If double-quotes are used to enclose fields,
			// then a double-quote appearing inside a field must be escaped by
			// preceding it with another double quote."
			std::wstring from = L"\"";
			std::wstring to = L"\"\"";

			ReplaceAll(value, from, to);

			columnLine += L"\"";
			columnLine += value;
			columnLine += L"\"";
			columnLine += L",";
		}
		else {
			columnLine += value;
			columnLine += L",";
		}

		i++;
	}
	std::wstring value = vColumns[i];

	// Wrap in double quotes if value contains a comma
	if (value.find(L',') != std::wstring::npos) {
		// RFC-4180, paragraph 7. "If double-quotes are used to enclose fields,
		// then a double-quote appearing inside a field must be escaped by
		// preceding it with another double quote."
		std::wstring from = L"\"";
		std::wstring to = L"\"\"";

		ReplaceAll(value, from, to);

		columnLine += L"\"";
		columnLine += value;
		columnLine += L"\"";
	}
	else {
		columnLine += value;
	}

	//std::wcout << columnLine << std::endl;
	csvFile << columnLine << std::endl;

	// Create/Write rows
	i = 0;
	while (i < vMapResults.size()) {
		std::wstring rowLine;

		j = 0;
		while (j < vColumns.size() - 1) {
			try {
				std::wstring value = vMapResults[i].at(vColumns[j]);

				// Wrap in double quotes if value contains a comma
				if (value.find(L',') != std::wstring::npos) {
					// RFC-4180 - paragraph 7 - "If double-quotes are used to enclose fields,
					// then a double-quote appearing inside a field must be escaped by
					// preceding it with another double quote."
					std::wstring from = L"\"";
					std::wstring to = L"\"\"";

					ReplaceAll(value, from, to);

					rowLine += L"\"";
					rowLine += value;
					rowLine += L"\"";
					rowLine += L",";
				}
				else {
					rowLine += value;
					rowLine += L",";
				}
			}
			catch (const std::out_of_range) {
				rowLine += L",";
			}

			j++;
		}
		try {
			std::wstring value = vMapResults[i].at(vColumns[j]);
			if (value.find(',') != std::wstring::npos) {
				// RFC-4180, paragraph "If double-quotes are used to enclose fields,
				// then a double-quote appearing inside a field must be escaped by
				// preceding it with another double quote."
				std::wstring from = L"\"";
				std::wstring to = L"\"\"";

				ReplaceAll(value, from, to);

				rowLine += L"\"";
				rowLine += value;
				rowLine += L"\"";
			}
			else {
				rowLine += value;
			}
		}
		catch (const std::out_of_range) {}

		//std::wcout << rowLine << std::endl;
		csvFile << rowLine << std::endl;
		rowLine.clear();

		i++;
	}

	csvFile.close();

	return TRUE;
}

BOOL IsTcpPortOpen(std::wstring host, std::wstring port, long timeoutSecs) {
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
					hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Convert host wstring to const char*
	const wchar_t* hostInput = host.c_str();
	size_t size = (wcslen(hostInput) + 1) * sizeof(wchar_t);
	char* hostBuf = new char[size];
	std::wcstombs(hostBuf, hostInput, size);

	// Convert port wstring to const char*
	const wchar_t* portInput = port.c_str();
	size = (wcslen(portInput) + 1) * sizeof(wchar_t);
	char* portBuf = new char[size];
	std::wcstombs(portBuf, portInput, size);

	if (getaddrinfo(hostBuf, portBuf, &hints, &result) != 0) {
		std::wcout << "Error: getaddrinfo failed" << std::endl;
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	// Create socket
	ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	if (ConnectSocket < 0) {
		std::wcout << L"Error: Failed to create a TCP socket." << std::endl;
		delete[] hostBuf;
		delete[] portBuf;
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	// Put socket in non-blocking mode
	u_long block = 1;
	if (ioctlsocket(ConnectSocket, FIONBIO, &block) == SOCKET_ERROR) {
		std::wcout << L"Error: Failed to put socket in non-blocking mode." << std::endl;
		closesocket(ConnectSocket);
		delete[] hostBuf;
		delete[] portBuf;
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	if ((connect(ConnectSocket, result->ai_addr, (int)result->ai_addrlen)) == SOCKET_ERROR) {
		if (WSAGetLastError() != WSAEWOULDBLOCK) {
			// Connection failed
			closesocket(ConnectSocket);
			delete[] hostBuf;
			delete[] portBuf;
			return FALSE;
		}

		// Connection pending
		fd_set setW, setE;

		FD_ZERO(&setW);
		FD_SET(ConnectSocket, &setW); // https://developercommunity.visualstudio.com/content/problem/1102463/fd-set-c6319-error.html
		FD_ZERO(&setE);
		FD_SET(ConnectSocket, &setE); // https://developercommunity.visualstudio.com/content/problem/1102463/fd-set-c6319-error.html

		timeval time_out = { 0 };
		time_out.tv_sec = timeoutSecs;
		time_out.tv_usec = 0;

		int ret = select(0, NULL, &setW, &setE, &time_out);

		if (ret <= 0) {
			// select() failed or connection timed out
			closesocket(ConnectSocket);
			
			if (ret == 0)
				WSASetLastError(WSAETIMEDOUT);

			delete[] hostBuf;
			delete[] portBuf;
			return FALSE;
		}

		if (FD_ISSET(ConnectSocket, &setE)) {
			// Connection failed
			closesocket(ConnectSocket);
			delete[] hostBuf;
			delete[] portBuf;
			return FALSE;
		}
	}
	else {
		// Connection Success, put back to blocking
		block = 0;
		if (ioctlsocket(ConnectSocket, FIONBIO, &block) != SOCKET_ERROR) {
			shutdown(ConnectSocket, SD_BOTH);
		}
		
		closesocket(ConnectSocket);
		delete[] hostBuf;
		delete[] portBuf;
		return TRUE;
	}

	return TRUE;
}

VOID StartScanning(std::vector <std::wstring> vwsArgs) {
	std::vector <std::map<std::wstring, std::wstring>> vMapResults;
	std::vector <std::wstring> vTargets;
	std::vector <std::wstring> vPorts;

	std::wstring targetHost;
	std::wstring targetsFile;
	std::wstring targetPorts;
	std::wstring csvFilePath;
	std::wstring scanTimeout;

	long timeoutSecs = SCAN_DEFAULT_TIMEOUT;

	BOOL bOutCsv  = FALSE;
	BOOL bVerbose = FALSE;
	BOOL bStatus  = FALSE;

	// Process command line arguments
	if (vwsArgs.size() == 0) {
		PrintUsage();
		return;
	}

	size_t i = 0;
	while (i < vwsArgs.size()) {
		if (vwsArgs[i] == L"-h") {
			PrintUsage();
			return;
		}
		else if (vwsArgs[i] == L"-t") {
			targetHost = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-tL") {
			targetsFile = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-p") {
			targetPorts = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-v") {
			bVerbose = TRUE;
			i += 1;
		}
		else if (vwsArgs[i] == L"--timeout") {
			scanTimeout = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"--csv") {
			csvFilePath = vwsArgs[i + 1];
			bOutCsv = TRUE;
			i += 2;
		}
	}

	// Populat targets vector
	if (targetPorts.empty() == TRUE) { // Verify target port(s) is/are defined
		std::wcout << L"Error: You must specify at least 1 port via '-p'\n" << std::endl;
		PrintUsage();
		return;
	}
	else {
		std::wstring::size_type prev_pos = 0, pos = 0;

		while ((pos = targetPorts.find(L",", pos)) != std::wstring::npos) {
			std::wstring substring(targetPorts.substr(prev_pos, pos - prev_pos));
			vPorts.push_back(substring);
			prev_pos = ++pos;
		}

		vPorts.push_back(targetPorts.substr(prev_pos, pos-prev_pos));
	}

	// Populat targets vector
	if (targetHost.empty() == FALSE) {
		vTargets.push_back(targetHost);
	}
	else if (targetsFile.empty() == FALSE) {
		std::wfstream fsTargets;
		fsTargets.open(targetsFile, std::ios::in);

		if (fsTargets.is_open()) {
			while (std::getline(fsTargets, targetHost)) {
				vTargets.push_back(targetHost);
			}
		}
		else {
			std::wcout << L"Error: Failed to open targets file\n" << std::endl;
			PrintUsage();
			return;
		}
	}
	else { // Verify at least one target is defined
		std::wcout << L"Error: You must specify target(s) with '-t' or '-tL'\n" << std::endl;
		PrintUsage();
		return;
	}

	// Configure connection timeout for scanning
	if (scanTimeout.empty() == FALSE)
		timeoutSecs = stol(scanTimeout);

	// Initialize winsock
	WSADATA mySock;
	if (WSAStartup(MAKEWORD(2, 0), &mySock) != 0) {
		std::wcout << L"Error: Failed to initialize winsock via WSAStartup()." << std::endl;
		exit(EXIT_FAILURE);
	}

	// Start port scanning
	UINT x = 0, y = 0;
	while (x < vTargets.size()) {
		y = 0;

		while (y < vPorts.size()) {
			std::map<std::wstring, std::wstring> mapResults;

			bStatus = IsTcpPortOpen(vTargets[x], vPorts[y], timeoutSecs);

			mapResults[L"Host"] = vTargets[x];
			mapResults[L"Port"] = vPorts[y];

			if (bStatus == TRUE) {
				std::wcout << vTargets[x] << L":" << vPorts[y] << L" OPEN" << std::endl;
				mapResults[L"Status"] = L"OPEN";
			}
			else if (bVerbose == TRUE) {
				std::wcout << vTargets[x] << L":" << vPorts[y] << L" CLOSED" << std::endl;
				mapResults[L"Status"] = L"CLOSED";
			}
			else {
				mapResults[L"Status"] = L"CLOSED";
			}

			vMapResults.push_back(mapResults);

			y++;
		}

		x++;
	}

	// Free any resources allocated by Ws2_32.dll
	WSACleanup();

	if (bOutCsv == TRUE) {
		// Save results to a CSV file
		bStatus = ResultsToCSV(vMapResults, csvFilePath);

		if (bStatus == FALSE)
			std::wcout << L"Error: ResultsToCSV() Failed" << std::endl;
	}
}