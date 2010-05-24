/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 3 %
*/

#ifndef _EAP_AUTOMATIC_H_
#define _EAP_AUTOMATIC_H_

template <class Type>
class PointerArrayResetAndDestroy
{

public:

	PointerArrayResetAndDestroy( RPointerArray<Type> * aArray, const TBool aDeleteWhenTrue)
		: iArray(aArray)
		, iDeleteWhenTrue(aDeleteWhenTrue)
	{
	}

	virtual ~PointerArrayResetAndDestroy()
	{
		if (iArray != 0)
		{
			iArray->ResetAndDestroy();
			iArray->Close();

			if (iDeleteWhenTrue)
			{
				delete iArray;
			}
			iArray = 0;
		}
	}

	void DoNotFreeArray()
	{
		iArray = 0;
	}

private:

	RPointerArray<Type> * iArray;

	TBool iDeleteWhenTrue;

};

#endif // _EAP_AUTOMATIC_H_

// End of file
