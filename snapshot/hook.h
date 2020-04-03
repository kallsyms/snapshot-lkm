#pragma once

int try_hook(const char *func_name, void *handler);
void unhook(const char *func_name);
void unhook_all(void);

