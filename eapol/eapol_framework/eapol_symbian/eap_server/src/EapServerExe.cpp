/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  scheduler of EAP-server.
*
*/

/*
* %version: 4 %
*/

#include "EapServer.h"

GLDEF_C TInt E32Main()
{
	CEapScheduler::TServerStart start;
	TInt r=CEapScheduler::ThreadStart(start);
	return r;
}

// End of file.
