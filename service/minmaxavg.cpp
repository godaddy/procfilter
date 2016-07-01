
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

