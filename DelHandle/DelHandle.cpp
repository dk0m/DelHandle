#include <iostream>
#include "./Jacker/Jacker.h"

const wchar_t* blacklisted[1] = {
	L"ProcessHacker.exe",
};

int main()
{
	while (true) {
		auto handles = Jacker::GetSysHandleInfo();

		for (size_t i = 0; i < handles->NumberOfHandles; i++)
		{
			auto uHandle = handles->Handles[i];
			auto dupHandle = Jacker::DupHandle(uHandle);

			if (!dupHandle)
				continue;

			auto handleInfo = Jacker::GetObjTypeInfo(dupHandle);

			if (handleInfo->TypeIndex != 7)
				continue;

			auto procId = GetProcessId(dupHandle);

			if (procId == GetCurrentProcessId()) {
				auto accessMask = uHandle.GrantedAccess;

				DWORD targetProcessId = (DWORD)uHandle.UniqueProcessId;
				LPWSTR targetProcessName = Jacker::GetProcessNameFromId(targetProcessId);
				
				for (const wchar_t* procName : blacklisted) {
					if (!wcscmp(procName, targetProcessName)) {
						if (CloseHandle(dupHandle)) {
							wprintf(L"Closed Handle, Process: %ls\n", procName);
							free(handleInfo);
						}

						
					}
				}
			}


		}

		
		free(handles);

		Sleep(5000);
	}
}
