
#pragma once

#include <Windows.h>

//
// Data internal to the MMA structure
//
typedef struct mma_data MMA_DATA;
struct mma_data {
	LONG64 llMin;      // Min value encountered
	LONG64 llMax;      // Max value encountered
	double rSma;       // The moving average
	LONG64 llNum;      // The number of values that have passed through the object
	LONG64 llTotalSum; // The sum of all values passed through the object
};

//
// Min, max, and average data
//
typedef struct mma_struct MMA;
struct mma_struct {
	struct {
		MMA_DATA md[1];      // The current data
		double rSmaAlpha;    // The alpha value specified during creation
		CRITICAL_SECTION cs; // Critical section protecting the structure elements
	} private_data[1];
};

//
// Moving average functions. All MmaXxx() functions are atomic.
//
void MmaInit(MMA *mma, double rWeight=.05);
void MmaDestroy(MMA *mma);

//
// Update the mma to include the specified value.
//
void MmaUpdate(MMA *mma, LONG64 llValue);

//
// Get the current average associated with the object.
//
MMA_DATA MmaGet(MMA *mma);

//
// Get the weight value that the object was constructed with.
//
double MmaGetWeight(MMA *mma);
