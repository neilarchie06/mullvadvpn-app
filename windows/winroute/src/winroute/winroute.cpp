#include "stdafx.h"
#include "winroute.h"
#include "NetworkInterfaces.h"
#include <cstdint>
#include <stdexcept>

extern "C"
WINROUTE_LINKAGE
int32_t
WINROUTE_API
WinRoute_EnsureTopMetric(
	const wchar_t *deviceAlias,
	WinRouteErrorSink errorSink,
	void* errorSinkContext
) {
	try
	{
		NetworkInterfaces interfaces;
		bool metrics_set = interfaces.SetTopMetricForInterfaceByAlias(deviceAlias);
		return metrics_set ? 1 : 0;
	}
	catch (std::exception &err) 
	{
		if (nullptr != errorSink)
		{
			errorSink(err.what(), errorSinkContext);
		}
		return -1;
	}
	catch (...)
	{
		return -1;
	}
};

