//
// The MIT License (MIT)
//
// Copyright (c) 2016 GoDaddy Operating Company, LLC.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//

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
