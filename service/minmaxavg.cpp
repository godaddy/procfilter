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

#include "minmaxavg.hpp"


void
MmaInit(MMA *mma, double rWeight)
{
	ZeroMemory(mma, sizeof(MMA));
	mma->private_data->rSmaAlpha = rWeight;
	mma->private_data->md->rSma = 0.0;
	InitializeCriticalSection(&mma->private_data->cs);
}


void
MmaDestroy(MMA *mma)
{
	DeleteCriticalSection(&mma->private_data->cs);
}


void
MmaUpdate(MMA *mma, LONG64 llValue)
{
	EnterCriticalSection(&mma->private_data->cs);
	MMA_DATA *md = mma->private_data->md;
	if (md->llNum == 0) {
		md->llMin = llValue;
		md->llMax = llValue;
	} else {
		if (llValue < md->llMin) md->llMin = llValue;
		if (llValue > md->llMax) md->llMax = llValue;
	}
	md->llNum += 1;
	md->llTotalSum += llValue;
	md->rSma = mma->private_data->rSmaAlpha * llValue + (1.0 - mma->private_data->rSmaAlpha) * md->rSma;
	LeaveCriticalSection(&mma->private_data->cs);
}


double
MmaGetWeight(MMA *mma)
{
	// Value is constant so no mutex lock needed to read it
	return mma->private_data->rSmaAlpha;
}


MMA_DATA
MmaGet(MMA *mma)
{
	EnterCriticalSection(&mma->private_data->cs);
	MMA_DATA mdResult = *mma->private_data->md;
	LeaveCriticalSection(&mma->private_data->cs);
	return mdResult;
}

