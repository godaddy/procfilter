
#pragma once

//
// Initialize and shutdown the fatal error subsystem
//
void DieInit();
void DieShutdown();

//
// Exit the program due to a fatal error
//
void __declspec(noreturn) _Die(const char *file, int line, const char *fmt, ...);
#define Die(fmt, ...) _Die(__FILE__, __LINE__, fmt, __VA_ARGS__)
