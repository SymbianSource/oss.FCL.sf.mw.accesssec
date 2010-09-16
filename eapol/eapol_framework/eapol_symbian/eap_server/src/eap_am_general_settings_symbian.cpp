/*
* Copyright (c) 2009-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP general settings configuration.
*
*/

/*
* %version: 61 %
*/

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
#include "eap_expanded_type.h"
#include "eap_array.h"
#include "eap_database_reference_if.h"
#include "eap_am_general_settings_symbian.h"
#include "abs_eap_am_general_settings.h"
#include "eap_automatic_variable.h"
#include "EapTraceSymbian.h"
#include "EapConversion.h"
#include "EapTlsPeapCertFetcher.h"
#include "EapPluginTools.h"
#include <EapTypePlugin.h>
#include "EapAutomatic.h"

/** @file */

// ----------------------------------------------------------------------

EAP_LITERAL_SYMBIAN(KGeneralsettingsDatabaseName, "eap_methods.dat");

EAP_LITERAL_SYMBIAN(KGeneralSettingsTableName, "eap_general_settings");

_LIT(KEapMethodEnabledValue, "enabled");
_LIT(KEapMethodDisabledValue, "disabled");

_LIT(KServiceType, "service_type");
_LIT(KServiceIndex, "service_index");

_LIT(KSQL, "SELECT %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d");

const TUint KMaxSqlQueryLength = 512;
const TInt	KDefaultColumnInView_One = 4; // For DB view.

// ----------------------------------------------------------------------

eap_am_general_settings_symbian_c::eap_am_general_settings_symbian_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_am_general_settings_c * const partner)
	: m_am_tools(tools)
	, m_partner(partner)
	, m_is_valid(false)
	, m_shutdown_was_called(false)
	, iGeneralSettingsDbCreated(EFalse)
	, iGeneralSettingsSessionOpened(EFalse)
	, iCertificateFetcher(0)
	, m_completion_status(eap_status_process_general_error)
	, m_EAPType(eap_type_none)
	, m_IndexType(0ul)
	, m_Index(0ul)
{
	if (m_am_tools == 0
		|| m_am_tools->get_is_valid() == false
		|| m_partner == 0)
	{
		return;
	}

	m_is_valid = true;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::eap_am_general_settings_symbian_c(): this=0x%08x.\n"),
		this));
}

// ----------------------------------------------------------------------

eap_am_general_settings_symbian_c::eap_am_general_settings_symbian_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_partner(0)
	, m_is_valid(false)
	, m_shutdown_was_called(false)
	, iGeneralSettingsDbCreated(EFalse)
	, iGeneralSettingsSessionOpened(EFalse)
	, iCertificateFetcher(0)
	, m_completion_status(eap_status_process_general_error)
	, m_EAPType(eap_type_none)
	, m_IndexType(0ul)
	, m_Index(0ul)
{
	if (m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		return;
	}

	m_is_valid = true;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::eap_am_general_settings_symbian_c(): this=0x%08x.\n"),
		this));
}

// ----------------------------------------------------------------------

eap_am_general_settings_symbian_c::~eap_am_general_settings_symbian_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::~eap_am_general_settings_symbian_c(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::~eap_am_general_settings_symbian_c()");

	EAP_UNREFERENCED_PARAMETER(KGeneralsettingsDatabaseName_8bit);

	EAP_UNREFERENCED_PARAMETER(KGeneralSettingsTableName_8bit);

	CloseGeneralSettings();

	delete iCertificateFetcher;
	iCertificateFetcher = 0;

	EAP_ASSERT(m_shutdown_was_called == true);
}

// ----------------------------------------------------------------------

bool eap_am_general_settings_symbian_c::get_is_valid()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::get_is_valid(): this=0x%08x, m_is_valid=%d.\n"),
		this,
		m_is_valid));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::get_is_valid()");

	return m_is_valid;
}

// ----------------------------------------------------------------------

// This is documented in abs_eap_stack_interface_c::configure().
eap_status_e eap_am_general_settings_symbian_c::configure()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::configure(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::configure()");

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// ----------------------------------------------------------------------

// This is documented in abs_eap_stack_interface_c::shutdown().
eap_status_e eap_am_general_settings_symbian_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::shutdown(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::shutdown()");

	m_shutdown_was_called = true;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// ----------------------------------------------------------------------

void eap_am_general_settings_symbian_c::CloseGeneralSettings()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CloseGeneralSettings(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::CloseGeneralSettings()");

	iGeneralSettingsDb.Close();
	iGeneralSettingsDbCreated = EFalse;

	iGeneralSettingsFileServerSession.Close();
	iGeneralSettingsSessionOpened = EFalse;
}

// ----------------------------------------------------------------------

void eap_am_general_settings_symbian_c::OpenGeneralSettingsL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::OpenGeneralSettingsL(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::OpenGeneralSettingsL()");

	if(iGeneralSettingsDbCreated == EFalse
		|| iGeneralSettingsSessionOpened == EFalse)
	{
		// The general settings store DB and tables are not created. So create it.
		CreateGeneralSettingsL();
	}
}

// ----------------------------------------------------------------------

void eap_am_general_settings_symbian_c::CreateGeneralSettingsL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CreateGeneralSettingsL(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::CreateGeneralSettingsL()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// 1. Open/create a database

	TInt error(KErrNone);

	// Connect to the DBMS server, if not connected already.
	if(iGeneralSettingsSessionOpened == EFalse)
	{
		error = iGeneralSettingsFileServerSession.Connect();
		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
		User::LeaveIfError(error);

		iGeneralSettingsSessionOpened = ETrue;
	}

	TFileName aPrivateDatabasePathName;

	EapPluginTools::CreateDatabaseLC(
		iGeneralSettingsDb,
		iGeneralSettingsFileServerSession,
		error,
		KGeneralsettingsDatabaseName,
		aPrivateDatabasePathName);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CreateGeneralSettingsL() - Created Secure DB for %S. error=%d (-11=DB already exist)\n"),
		&KGeneralsettingsDatabaseName_8bit,
		error) );

	if(error == KErrNone)
	{
		// Database is closed if it was created in EapPluginTools::CreateDatabaseLC().
		// If database exists it was not opened in EapPluginTools::CreateDatabaseLC().
		iGeneralSettingsDb.Close();
	}
	else if (error != KErrAlreadyExists)
	{
		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
		User::LeaveIfError(error);
	}

	error = iGeneralSettingsDb.Open(iGeneralSettingsFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CreateGeneralSettingsL() - Open Secure DB for %S. error=%d (-11=DB already exist)\n"),
		&KGeneralsettingsDatabaseName_8bit,
		error) );

	User::LeaveIfError(error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// 2. Create the tables to database (ignore error if tables exist)

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Create table for enabled and disabled EAP-types.

	//// NAME //////////////////// TYPE ///////////// Constant ////////////////////
	//| ServiceType				| UNSIGNED INTEGER | KServiceType				|//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex				|//
	//| Enabled EAP-methods		| LONG VARBINARY   | KEapMethodEnabledValue		|//
	//| Disabled EAP-methods	| LONG VARBINARY   | KEapMethodDisabledValue	|//
	///////////////////////////////////////////////////////////////////////////////

	_LIT(KSQLCreateTable2, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
		%S UNSIGNED INTEGER, \
		%S LONG VARBINARY, \
		%S LONG VARBINARY)");

	sqlStatement.Format(
		KSQLCreateTable2,
		&KGeneralSettingsTableName,
		&KServiceType,
		&KServiceIndex,
		&KEapMethodEnabledValue,
		&KEapMethodDisabledValue);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CreateGeneralSettingsL() - SQL query formated OK\n")));

	error = iGeneralSettingsDb.Execute(sqlStatement);
	if (error != KErrNone
		&& error != KErrAlreadyExists)
	{
		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
		User::Leave(error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CreateGeneralSettingsL() Created Groups table\n")));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	CleanupStack::PopAndDestroy( buf );
	CleanupStack::Pop(&iGeneralSettingsDb);
	CleanupStack::Pop(&iGeneralSettingsFileServerSession);

	iGeneralSettingsDbCreated = ETrue;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CreateGeneralSettingsL(): End \n")));	

} // eap_am_general_settings_symbian_c::CreateGeneralSettingsL()

// ----------------------------------------------------------------------

void eap_am_general_settings_symbian_c::GetGeneralSettingsLongBinaryL(
	RDbView &aViev,
	const TDesC &aColName,
	HBufC8** const aMethods)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsLongBinaryL(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::GetGeneralSettingsLongBinaryL()");

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = aViev.ColSetL();
	CleanupStack::PushL(colSet);

	TDbColNo colNoReference = 0;
	colNoReference = colSet->ColNo(aColName);

	switch (aViev.ColType(colNoReference))
	{
		case EDbColLongBinary:
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsLongBinaryL() - Long Binary column"),
				aColName.Ptr(),
				aColName.Size()));

			// A stream is needed for LONG columns in DB.
			RDbColReadStream readStream;

			// Get the value from DB.
			HBufC8* valueBuf = HBufC8::NewLC(aViev.ColLength(colNoReference)); // Buffer for the data.
			TPtr8 value8 = valueBuf->Des();

			readStream.OpenLC(aViev, colNoReference);
			readStream.ReadL(value8, aViev.ColLength(colNoReference));
			readStream.Close();
			CleanupStack::PopAndDestroy(&readStream);

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsLongBinaryL(): LONG BINARY value from DB"),
				value8.Ptr(), 
				value8.Size()));

			*aMethods = HBufC8::New(value8.Size());

			// This to avoid the use of clean up stack for output parameter.
			if ((*aMethods) != 0)
			{
				TPtr8 aDbBinaryColumnValuePtr = (*aMethods)->Des();			

				aDbBinaryColumnValuePtr.Copy(value8);

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsLongBinaryL(): LONG BINARY value to caller"),
					aDbBinaryColumnValuePtr.Ptr(), 
					aDbBinaryColumnValuePtr.Size()));
			}
			else
			{
				User::Leave(KErrNoMemory);
			}

			CleanupStack::PopAndDestroy(valueBuf);

			break;
		}
		default:
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: eap_am_general_settings_symbian_c::GetGeneralSettingsLongBinaryL(): Unsupported DB field:%d = %S\n"),
				aViev.ColType(colNoReference),
				&aColName));	

			User::Leave(KErrNotSupported);
			break;
	} // End: switch ()

	CleanupStack::PopAndDestroy(colSet);
}

// ----------------------------------------------------------------------

void eap_am_general_settings_symbian_c::GetGeneralSettingsDataL(
	const TUint indexType,
	const TUint index,
	HBufC8** const aEnabledEapMethods,
	HBufC8** const aDisabledEapMethods)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsDataL(): iGeneralSettingsSessionOpened=%d, iGeneralSettingsDbCreated=%d"),
		iGeneralSettingsSessionOpened,
		iGeneralSettingsDbCreated));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::GetGeneralSettingsDataL()");

	*aEnabledEapMethods = 0;
	*aDisabledEapMethods = 0;

	if(iGeneralSettingsSessionOpened == EFalse)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsDataL(): ERROR: General settings session not opened!")));

		User::Leave(KErrSessionClosed);
	}	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	sqlStatement.Format(
		KSQL,
		&KServiceType,
		&KServiceIndex,
		&KEapMethodEnabledValue,
		&KEapMethodDisabledValue,
		&KGeneralSettingsTableName,
		&KServiceType,
		indexType,
		&KServiceIndex,
		index);


	RDbView view;

	User::LeaveIfError(view.Prepare(
		iGeneralSettingsDb, 
		TDbQuery(sqlStatement), 
		TDbWindow::EUnlimited,
		RDbView::EReadOnly));

	CleanupClosePushL(view);

	User::LeaveIfError(view.EvaluateAll());

	if (view.IsEmptyL())
	{				
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsDataL(): No entries in this table (%S) RETURN EMPTY VALUE"),
			&KGeneralSettingsTableName_8bit));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsDataL():sqlStatement"),
			sqlStatement.Ptr(), 
			sqlStatement.Size()));

		CleanupStack::PopAndDestroy(&view);

		CleanupStack::PopAndDestroy(buf);	

		return;
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsDataL(): Number of entries in table %S=%d"),
			&KGeneralSettingsTableName_8bit, view.CountL()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsDataL() - view evaluated OK\n")));


	if (view.FirstL())
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsDataL() - First OK\n")));

		view.GetL();

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsDataL() - First Got\n")));

		GetGeneralSettingsLongBinaryL(view, KEapMethodEnabledValue, aEnabledEapMethods);

		GetGeneralSettingsLongBinaryL(view, KEapMethodDisabledValue, aDisabledEapMethods);
	}

	CleanupStack::PopAndDestroy( &view );

	CleanupStack::PopAndDestroy(buf); // We don't need buf or sqlStatement any more.

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::GetGeneralSettingsDataL(): End")));	
}

// ----------------------------------------------------------------------

void eap_am_general_settings_symbian_c::SetGeneralSettingsLongBinaryL(
	RDbView &aViev,
	const TDesC &aColName,
	const TDesC8& aMethods)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::SetGeneralSettingsLongBinaryL(): iGeneralSettingsSessionOpened=%d, iGeneralSettingsDbCreated=%d"),
		iGeneralSettingsSessionOpened,
		iGeneralSettingsDbCreated));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::SetGeneralSettingsLongBinaryL()");

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = aViev.ColSetL();
	CleanupStack::PushL(colSet);

	TDbColNo colNoReference = 0;
	colNoReference = colSet->ColNo(aColName);

	switch (aViev.ColType(colNoReference))
	{
		case EDbColLongBinary:
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_general_settings_symbian_c::SetGeneralSettingsLongBinaryL() - Long Binary column"),
				aColName.Ptr(), 
				aColName.Size()));

			// A stream is needed for LONG columns in DB.
			RDbColWriteStream writeStream;					
			writeStream.OpenLC( aViev, colNoReference );
			writeStream.WriteL( aMethods );
			writeStream.Close();
			CleanupStack::PopAndDestroy( &writeStream );
			break;
		}
		default:
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("eap_am_general_settings_symbian_c::SetGeneralSettingsLongBinaryL(): ERROR: Unsupported DB field:%d = %S\n"),
				aViev.ColType(colNoReference),
				&aColName));	

			User::Leave(KErrNotSupported);
			break;

	} // End: switch (aViev.ColType(colNoReference))

	CleanupStack::PopAndDestroy(colSet);
}

//-------------------------------------------------------------

void eap_am_general_settings_symbian_c::SetGeneralSettingsDataL(
	const TUint indexType,
	const TUint index,
	const TDesC8& aEnabledEapMethods,
	const TDesC8& aDisabledEapMethods)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::SetGeneralSettingsDataL(): iGeneralSettingsSessionOpened=%d, iGeneralSettingsDbCreated=%d"),
		iGeneralSettingsSessionOpened, iGeneralSettingsDbCreated));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::SetGeneralSettingsDataL()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::SetGeneralSettingsDataL(): Set this value in general settings DB"),
		aEnabledEapMethods.Ptr(),
		aEnabledEapMethods.Size()));

	if(iGeneralSettingsSessionOpened == EFalse)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_general_settings_symbian_c::SetGeneralSettingsDataL(): ERROR: General settings session not opened!")));

		User::Leave(KErrSessionClosed);
	}	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	sqlStatement.Format(
		KSQL,
		&KServiceType,
		&KServiceIndex,
		&KEapMethodEnabledValue,
		&KEapMethodDisabledValue,
		&KGeneralSettingsTableName,
		&KServiceType,
		indexType,
		&KServiceIndex,
		index);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::SetGeneralSettingsDataL():sqlStatement"),
		sqlStatement.Ptr(), 
		sqlStatement.Size()));

	RDbView view;

	User::LeaveIfError(view.Prepare(
		iGeneralSettingsDb, 
		TDbQuery(sqlStatement), 
		TDbWindow::EUnlimited,
		RDbView::EUpdatable));

	CleanupClosePushL(view);

	User::LeaveIfError(view.EvaluateAll());

	{	
		if(view.ColCount() != KDefaultColumnInView_One)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("eap_am_general_settings_symbian_c::SetGeneralSettingsDataL(): ERROR: Problem with rows or columns in DB view, view.IsEmptyL()=%d, row count=%d, col count=%d \n"),
				view.IsEmptyL(),
				view.CountL(),
				view.ColCount()));	

			User::Leave(KErrNotFound);				
		}	

		if (view.FirstL())
		{
			view.UpdateL(); // Here it is update.
		}
		else
		{
			view.InsertL(); // Here it is insert.
		}

		{
			CDbColSet* colSet = view.ColSetL();
			CleanupStack::PushL(colSet);		

			TDbColNo colNoServiceType = 0;
			TDbColNo colNoServiceIndex = 0;

			colNoServiceType = colSet->ColNo(KServiceType);
			colNoServiceIndex = colSet->ColNo(KServiceIndex);		
			
			CleanupStack::PopAndDestroy(colSet); // delete colSet.

			view.SetColL(colNoServiceType, indexType);
			view.SetColL(colNoServiceIndex, index);

			SetGeneralSettingsLongBinaryL(view,	KEapMethodEnabledValue, aEnabledEapMethods);

			SetGeneralSettingsLongBinaryL(view,	KEapMethodDisabledValue, aDisabledEapMethods);
		}
	}

	// Now it should go to the DB.
	view.PutL();	

	CleanupStack::PopAndDestroy( &view );

	CleanupStack::PopAndDestroy(buf);
}

//-------------------------------------------------------------

void eap_am_general_settings_symbian_c::DeleteGeneralSettingsDataL(
	const TUint indexType,
	const TUint index)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::DeleteGeneralSettingsDataL(): iGeneralSettingsSessionOpened=%d, iGeneralSettingsDbCreated=%d"),
		iGeneralSettingsSessionOpened, iGeneralSettingsDbCreated));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::DeleteGeneralSettingsDataL()");

	if(iGeneralSettingsSessionOpened == EFalse)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_general_settings_symbian_c::DeleteGeneralSettingsDataL(): ERROR: General settings session not opened!")));

		User::Leave(KErrSessionClosed);
	}	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	sqlStatement.Format(
		KSQL,
		&KServiceType,
		&KServiceIndex,
		&KEapMethodEnabledValue,
		&KEapMethodDisabledValue,
		&KGeneralSettingsTableName,
		&KServiceType,
		indexType,
		&KServiceIndex,
		index);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::DeleteGeneralSettingsDataL():sqlStatement"),
		sqlStatement.Ptr(), 
		sqlStatement.Size()));

	RDbView view;

	User::LeaveIfError(view.Prepare(
		iGeneralSettingsDb, 
		TDbQuery(sqlStatement), 
		TDbWindow::EUnlimited,
		RDbView::EUpdatable));

	CleanupClosePushL(view);

	User::LeaveIfError(view.EvaluateAll());

	{	
		// Delete old row and also rows that are for same IAP.
		if (view.FirstL())
		{
			CDbColSet* colSet = view.ColSetL();
			CleanupStack::PushL(colSet);

			do {
				view.GetL();

				if (view.ColUint32(colSet->ColNo(KServiceType)) == static_cast<TUint>(indexType)
						&& view.ColUint32(colSet->ColNo(KServiceIndex)) == static_cast<TUint>(index))
				{
					view.DeleteL();
				}
				
			} while (view.NextL() != EFalse);

			CleanupStack::PopAndDestroy(colSet); // delete colSet.
		}
	}

	CleanupStack::PopAndDestroy( &view );

	CleanupStack::PopAndDestroy(buf);
}

// ----------------------------------------------------------------------

void eap_am_general_settings_symbian_c::CopyGeneralSettingsDataL(
	const TUint aSourceIndexType,
	const TUint aSourceIndex,
	const TUint aDestinationIndexType,
	const TUint aDestinationIndex)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CopyGeneralSettingsDataL(): iGeneralSettingsSessionOpened=%d, iGeneralSettingsDbCreated=%d"),
		iGeneralSettingsSessionOpened, iGeneralSettingsDbCreated));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::CopyGeneralSettingsDataL()");

	if(iGeneralSettingsSessionOpened == EFalse)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_general_settings_symbian_c::CopyGeneralSettingsDataL(): ERROR: General settings session not opened!")));

		User::Leave(KErrSessionClosed);
	}

	if (aSourceIndexType == aDestinationIndexType
		&& aSourceIndex == aDestinationIndex)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_general_settings_symbian_c::CopyGeneralSettingsDataL(): ERROR: aSourceIndexType == aDestinationIndexType && aSourceIndex == aDestinationIndex")));

		User::Leave(KErrArgument);
	}

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	sqlStatement.Format(
		KSQL,
		&KServiceType,
		&KServiceIndex,
		&KEapMethodEnabledValue,
		&KEapMethodDisabledValue,
		&KGeneralSettingsTableName,
		&KServiceType,
		aDestinationIndexType,
		&KServiceIndex,
		aDestinationIndex);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CopyGeneralSettingsDataL():sqlStatement"),
		sqlStatement.Ptr(), 
		sqlStatement.Size()));

	RDbView view;

	User::LeaveIfError(view.Prepare(
		iGeneralSettingsDb, 
		TDbQuery(sqlStatement), 
		TDbWindow::EUnlimited,
		RDbView::EUpdatable));

	CleanupClosePushL(view);

	User::LeaveIfError(view.EvaluateAll());

	{	
		// Delete destination old data.
		if (view.FirstL())
		{
			CDbColSet* colSet = view.ColSetL();
			CleanupStack::PushL(colSet);

  			do 
  			{
	  			view.GetL();

				if (view.ColUint(colSet->ColNo(KServiceType)) == static_cast<TUint>(aDestinationIndexType)
					&& view.ColUint(colSet->ColNo(KServiceIndex)) == static_cast<TUint>(aDestinationIndex))
				{  		
      				EAP_TRACE_DEBUG_SYMBIAN((_L("eap_am_general_settings_symbian_c::CopyGeneralSettingsDataL(): Delete old records\n") ) );
      				view.DeleteL();
   				}
			}
			while (view.NextL() != EFalse);

			view.Close();

			CleanupStack::PopAndDestroy(colSet); // delete colSet.
		}

		sqlStatement.Format(
			KSQL,
			&KServiceType,
			&KServiceIndex,
			&KEapMethodEnabledValue,
			&KEapMethodDisabledValue,
			&KGeneralSettingsTableName,
			&KServiceType,
			aSourceIndexType,
			&KServiceIndex,
			aSourceIndex);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::CopyGeneralSettingsDataL():sqlStatement"),
			sqlStatement.Ptr(), 
			sqlStatement.Size()));

		User::LeaveIfError(view.Prepare(
			iGeneralSettingsDb, 
			TDbQuery(sqlStatement), 
			TDbWindow::EUnlimited,
			RDbView::EUpdatable));

		User::LeaveIfError(view.EvaluateAll());

		// Copy source row to destination.
		if (view.FirstL())
		{
			CDbColSet* colSet = view.ColSetL();
			CleanupStack::PushL(colSet);
			TDbBookmark bookmark;

			do
			{
				view.GetL();

				if (view.ColUint32(colSet->ColNo(KServiceType)) == static_cast<TUint>(aSourceIndexType)
						&& view.ColUint32(colSet->ColNo(KServiceIndex)) == static_cast<TUint>(aSourceIndex))
				{	
					bookmark = view.Bookmark();
					
					view.InsertCopyL();
					
					view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aDestinationIndexType));
	    			view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(aDestinationIndex));
					
					view.PutL();
				
					view.GotoL(bookmark);
				}
				
			}
			while (view.NextL() != EFalse);

			CleanupStack::PopAndDestroy(colSet); // delete colSet.
		}
	}

	CleanupStack::PopAndDestroy( &view );

	CleanupStack::PopAndDestroy(buf);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_general_settings_symbian_c::error_complete(
	const eap_status_e completion_status,
	const eap_method_settings_c * const internal_settings,
	const eap_tlv_message_type_function_e error_completion_function)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::error_complete(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::error_complete()");

	CloseGeneralSettings();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::error_complete(): this=0x%08x, CloseGeneralSettings()\n"),
		this));

	if (internal_settings == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools, internal_settings);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	complete_settings->m_completion_status = completion_status;

	eap_status_e status(eap_status_not_supported);

	switch(error_completion_function)
	{
	case eap_tlv_message_type_function_general_settings_complete_get_eap_methods:
		status = m_partner->complete_get_eap_methods(complete_settings);
		break;
	case eap_tlv_message_type_function_general_settings_complete_set_eap_methods:
		status = m_partner->complete_set_eap_methods(complete_settings);
		break;
	case eap_tlv_message_type_function_general_settings_complete_get_certificate_lists:
		status = m_partner->complete_get_certificate_lists(complete_settings);
		break;
	case eap_tlv_message_type_function_general_settings_complete_delete_all_eap_settings:
		status = m_partner->complete_delete_all_eap_settings(complete_settings);
		break;
	case eap_tlv_message_type_function_general_settings_complete_copy_all_eap_settings:
		status = m_partner->complete_copy_all_eap_settings(complete_settings);
		break;
	default:
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::error_complete(): unknown function %d.\n"),
			 error_completion_function));

		EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_general_settings_symbian_c::filter_eap_methods(
	eap_array_c<eap_type_value_e> * const eap_methods,
	RPointerArray<TEapExpandedType> * const aPlugins)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::filter_eap_methods(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::filter_eap_methods()");

	eap_status_e status(eap_status_ok);

	for (TInt act_ind = 0; act_ind < eap_methods->get_object_count(); ++act_ind)
	{
		const eap_type_value_e * active_type = eap_methods->get_object(act_ind);
		if (active_type == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::filter_eap_methods(): eap_methods[%d] EAP-type=0xfe%06x%08x\n"),
			act_ind,
			active_type->get_vendor_id(),
			active_type->get_vendor_type()));

		bool exists(false);

		for (TInt plugin_ind = 0; plugin_ind < aPlugins->Count(); ++plugin_ind)
		{
			const TEapExpandedType * eap_type = (*aPlugins)[plugin_ind];
			if (eap_type == 0)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DEBUG_SYMBIAN((_L("eap_am_general_settings_symbian_c::filter_eap_methods(): aPlugins[%d] EAP-type=0xfe%06x%08x\n"),
				plugin_ind,
				eap_type->GetVendorId(),
				eap_type->GetVendorType()));

			const eap_type_value_e common_eap_type(
				static_cast<eap_type_vendor_id_e>(eap_type->GetVendorId()),
				eap_type->GetVendorType());

			if (common_eap_type == *active_type)
			{
				// OK, this active EAP-method have implementation.
				exists = true;

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::filter_eap_methods(): Removes from aPlugins EAP-type=0xfe%06x%08x\n"),
					common_eap_type.get_vendor_id(),
					common_eap_type.get_vendor_type()));

				// Remove this plugin EAP-method because it is in the list of EAP-methods.
				delete (*aPlugins)[plugin_ind];
				aPlugins->Remove(plugin_ind);

				break;
			}
		} // for()

		if (exists == false)
		{
			// Remove this EAP-method because there are no implementation.

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_general_settings_symbian_c::filter_eap_methods(): Removes from eap_methods EAP-type=0xfe%06x%08x\n"),
				active_type->get_vendor_id(),
				active_type->get_vendor_type()));

			status = eap_methods->remove_object(act_ind);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			--act_ind;
		}
	} // for()

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_general_settings_symbian_c::read_eap_methods_synchronously(
	const TUint indexType,
	const TUint index,
	eap_array_c<eap_type_value_e> * const aEnabledEapMethodsArray,
	eap_array_c<eap_type_value_e> * const aDisabledEapMethodsArray)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::read_eap_methods_synchronously()");

	TInt error = KErrNone;

	TRAP(error, (OpenGeneralSettingsL()));

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): OpenGeneralSettingsL() failed, indexType=%d, index=%d, error=%d.\n"),
			indexType,
			index,
			error));

		CloseGeneralSettings();

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): this=0x%08x, CloseGeneralSettings()\n"),
			this));

		return EAP_STATUS_RETURN(
			m_am_tools,
			m_am_tools->convert_am_error_to_eapol_error(error));
	}


	HBufC8 *aEnabledEapMethods = 0;
	HBufC8 *aDisabledEapMethods = 0;

	// The output parameters aEnabledEapMethods and aDisabledEapMethods are NOT in clean up stack.
	TRAP(error, (GetGeneralSettingsDataL(
		indexType,
		index,
		&aEnabledEapMethods,
		&aDisabledEapMethods)));

	eap_automatic_variable_c<HBufC8> automatic_aEnabledEapMethods(
		m_am_tools,
		aEnabledEapMethods);

	eap_automatic_variable_c<HBufC8> automatic_aDisabledEapMethods(
		m_am_tools,
		aDisabledEapMethods);

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): GetGeneralSettingsDataL() failed, index_type=%d, index=%d, error=%d.\n"),
			indexType,
			index,
			error));

		CloseGeneralSettings();

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): this=0x%08x, CloseGeneralSettings()\n"),
			this));

		return EAP_STATUS_RETURN(
			m_am_tools,
			m_am_tools->convert_am_error_to_eapol_error(error));
	}

	if (aEnabledEapMethods != 0)
	{
		error = CEapConversion::ConvertHBufC8ToInternalTypes(
			m_am_tools,
			aEnabledEapMethods,
			aEnabledEapMethodsArray);

		if (error != KErrNone)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): index_type=%d, index=%d.\n"),
				indexType,
				index));

			CloseGeneralSettings();

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): this=0x%08x, CloseGeneralSettings()\n"),
				this));

			return EAP_STATUS_RETURN(
				m_am_tools,
				m_am_tools->convert_am_error_to_eapol_error(error));
		}
	}

	if (aDisabledEapMethods != 0)
	{
		error = CEapConversion::ConvertHBufC8ToInternalTypes(
			m_am_tools,
			aDisabledEapMethods,
			aDisabledEapMethodsArray);

		if (error != KErrNone)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): index_type=%d, index=%d.\n"),
				indexType,
				index));

			CloseGeneralSettings();

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): this=0x%08x, CloseGeneralSettings()\n"),
				this));

			return EAP_STATUS_RETURN(
				m_am_tools,
				m_am_tools->convert_am_error_to_eapol_error(error));
		}
	}

	iGeneralSettingsDb.Compact();

	CloseGeneralSettings();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::read_eap_methods_synchronously(): this=0x%08x, CloseGeneralSettings()\n"),
		this));

	return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
}

// ----------------------------------------------------------------------

eap_status_e eap_am_general_settings_symbian_c::get_eap_methods(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::get_eap_methods(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::get_eap_methods()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_general_settings_complete_get_eap_methods);

	HBufC8 *aEnabledEapMethods = 0;
	HBufC8 *aDisabledEapMethods = 0;

	TInt error(KErrNone);
	eap_status_e status(eap_status_ok);

	TRAP(error, (OpenGeneralSettingsL()));

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::get_eap_methods(): OpenGeneralSettingsL() failed, EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			error));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}


	// The output parameters aEnabledEapMethods and aDisabledEapMethods are NOT in clean up stack.
	TRAP(error, (GetGeneralSettingsDataL(
		internal_settings->m_IndexType,
		internal_settings->m_Index,
		&aEnabledEapMethods,
		&aDisabledEapMethods)));

	eap_automatic_variable_c<HBufC8> automatic_aEnabledEapMethods(
		m_am_tools,
		aEnabledEapMethods);

	eap_automatic_variable_c<HBufC8> automatic_aDisabledEapMethods(
		m_am_tools,
		aDisabledEapMethods);

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::get_eap_methods(): GetGeneralSettingsDataL() failed, EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			error));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}


	RPointerArray<TEapExpandedType> plugins_array;

	PointerArrayResetAndDestroy<TEapExpandedType> aAutomaticPlugins(&plugins_array, EFalse);

	EapPluginTools aPluginTool;

	TEapExpandedType aTunnelingType(*EapExpandedTypeNone.GetType());

	TRAP(error, (aPluginTool.ListAllEapPluginsL(static_cast<TIndexType>(internal_settings->m_IndexType), aTunnelingType, plugins_array)));
	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::get_eap_methods(): aPluginTool.ListAllEapPluginsL() failed, EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			error));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	if (aEnabledEapMethods != 0)
	{
		error = CEapConversion::ConvertHBufC8ToInternalTypes(
			m_am_tools,
			aEnabledEapMethods,
			&(complete_settings->m_active_eap_methods));

		if (error != KErrNone)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: eap_am_general_settings_symbian_c::get_eap_methods(): EAP-type=0xfe%06x%08x, index_type=%d, index=%d.\n"),
				internal_settings->m_EAPType.get_vendor_id(),
				internal_settings->m_EAPType.get_vendor_type(),
				internal_settings->m_IndexType,
				internal_settings->m_Index));
			return EAP_STATUS_RETURN(
				m_am_tools,
				error_complete(
					m_am_tools->convert_am_error_to_eapol_error(error),
					internal_settings,
					error_completion_function));
		}
	}

	if (aDisabledEapMethods != 0)
	{
		error = CEapConversion::ConvertHBufC8ToInternalTypes(
			m_am_tools,
			aDisabledEapMethods,
			&(complete_settings->m_disabled_eap_methods));

		if (error != KErrNone)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: eap_am_general_settings_symbian_c::get_eap_methods(): EAP-type=0xfe%06x%08x, index_type=%d, index=%d.\n"),
				internal_settings->m_EAPType.get_vendor_id(),
				internal_settings->m_EAPType.get_vendor_type(),
				internal_settings->m_IndexType,
				internal_settings->m_Index));
			return EAP_STATUS_RETURN(
				m_am_tools,
				error_complete(
					m_am_tools->convert_am_error_to_eapol_error(error),
					internal_settings,
					error_completion_function));
		}
	}

	// Next filter out unimplemented EAP-methods.
	status = filter_eap_methods(
		&(complete_settings->m_active_eap_methods),
		&plugins_array);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				status,
				internal_settings,
				error_completion_function));
	}

	// Check the disabled EAP-method have implementation.
	status = filter_eap_methods(
		&(complete_settings->m_disabled_eap_methods),
		&plugins_array);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				status,
				internal_settings,
				error_completion_function));
	}

	// Add the rest of the implemented EAP-methods to the disabled EAP-methods.
	for (TInt plugin_ind = 0; plugin_ind < plugins_array.Count(); ++plugin_ind)
	{
		const TEapExpandedType * eap_type = plugins_array[plugin_ind];
		if (eap_type == 0)
		{
			return EAP_STATUS_RETURN(
				m_am_tools,
				error_complete(
					eap_status_allocation_error,
					internal_settings,
					error_completion_function));
		}

		const eap_type_value_e common_eap_type(
			static_cast<eap_type_vendor_id_e>(eap_type->GetVendorId()),
			eap_type->GetVendorType());

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::get_eap_methods(): Adds disabled EAP-type=0xfe%06x%08x\n"),
			eap_type->GetVendorId(),
			eap_type->GetVendorType()));

		status = complete_settings->m_disabled_eap_methods.add_object(common_eap_type.copy(), true);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(
				m_am_tools,
				error_complete(
					status,
					internal_settings,
					error_completion_function));
		}
	} // for()

	complete_settings->m_SelectedEAPTypesPresent = true;

	complete_settings->m_completion_status = eap_status_ok;
	complete_settings->m_EAPType = internal_settings->m_EAPType;
	complete_settings->m_IndexType = internal_settings->m_IndexType;
	complete_settings->m_Index = internal_settings->m_Index;

	status = m_partner->complete_get_eap_methods(complete_settings);


	iGeneralSettingsDb.Compact();

	CloseGeneralSettings();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::get_eap_methods(): this=0x%08x, CloseGeneralSettings()\n"),
		this));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_general_settings_symbian_c::set_eap_methods(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::set_eap_methods(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::set_eap_methods()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_general_settings_complete_set_eap_methods);

	TInt error = KErrNone;

	TRAP(error, (OpenGeneralSettingsL()));

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::set_eap_methods(): OpenGeneralSettingsL() failed, EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			error));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}


	HBufC8 *aEnabledEapMethods = 0;
	HBufC8 *aDisabledEapMethods = 0;

	error = CEapConversion::ConvertInternalTypesToHBufC8(
		m_am_tools,
		&(internal_settings->m_active_eap_methods),
		&aEnabledEapMethods);

	eap_automatic_variable_c<HBufC8> automatic_aEnabledEapMethods(
		m_am_tools,
		aEnabledEapMethods);

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::set_eap_methods(): EAP-type=0xfe%06x%08x, index_type=%d, index=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index));
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	error = CEapConversion::ConvertInternalTypesToHBufC8(
		m_am_tools,
		&(internal_settings->m_disabled_eap_methods),
		&aDisabledEapMethods);

	eap_automatic_variable_c<HBufC8> automatic_aDisabledEapMethods(
		m_am_tools,
		aDisabledEapMethods);

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::set_eap_methods(): EAP-type=0xfe%06x%08x, index_type=%d, index=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index));
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	TRAP(error, (SetGeneralSettingsDataL(
		internal_settings->m_IndexType,
		internal_settings->m_Index,
		*aEnabledEapMethods,
		*aDisabledEapMethods)));
	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::set_eap_methods(): EAP-type=0xfe%06x%08x, index_type=%d, index=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index));
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	complete_settings->m_completion_status = eap_status_ok;
	complete_settings->m_EAPType = internal_settings->m_EAPType;
	complete_settings->m_IndexType = internal_settings->m_IndexType;
	complete_settings->m_Index = internal_settings->m_Index;

	eap_status_e status = m_partner->complete_set_eap_methods(complete_settings);

	iGeneralSettingsDb.Compact();

	CloseGeneralSettings();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::set_eap_methods(): this=0x%08x, CloseGeneralSettings()\n"),
		this));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_general_settings_symbian_c::get_certificate_lists(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::get_certificate_lists(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::get_certificate_lists()");

	TInt error(KErrNone);

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_general_settings_complete_get_certificate_lists);

	if (iCertificateFetcher == 0)
	{
		TRAP(error, iCertificateFetcher = CEapTlsPeapCertFetcher::NewL(this));
		if (error != KErrNone)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: eap_am_general_settings_symbian_c::get_certificate_lists(): this=0x%08x: CEapTlsPeapCertFetcher::NewL() failed=%d\n"),
				this,
				error));

			eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools);

			eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
				m_am_tools,
				complete_settings);

			return EAP_STATUS_RETURN(
				m_am_tools,
				error_complete(
					m_am_tools->convert_am_error_to_eapol_error(error),
					complete_settings,
					error_completion_function));
		}
	}

	m_completion_status = internal_settings->m_completion_status;
	m_EAPType = internal_settings->m_EAPType;
	m_IndexType = internal_settings->m_IndexType;
	m_Index = internal_settings->m_Index;

	TRAP(error, (iCertificateFetcher->GetCertificatesL()));
	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::get_certificate_lists(): iCertificateFetcher->GetCertificatesL(), error=%d\n"),
			error));
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	CloseGeneralSettings();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::get_certificate_lists(): this=0x%08x, CloseGeneralSettings()\n"),
		this));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// ----------------------------------------------------------

void eap_am_general_settings_symbian_c::CompleteReadCertificatesL(
		const RPointerArray<EapCertificateEntry>& aAvailableUserCerts, 
		const RPointerArray<EapCertificateEntry>& aAvailableCACerts)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::CompleteReadCertificatesL(): - Available cert count in device - USER=%d, CA=%d \n"),
		aAvailableUserCerts.Count(),
		aAvailableCACerts.Count()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::CompleteReadCertificatesL()");

	// Now all available certificates have been read.

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_general_settings_complete_get_certificate_lists);

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, error_complete(
			eap_status_allocation_error,
			complete_settings,
			error_completion_function));
	}

	TInt error = CEapConversion::ConvertCertificatesToInternalType(
		m_am_tools,
		&aAvailableUserCerts,
		&(complete_settings->m_Certificates));
	if (error != KErrNone)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, error_complete(
			m_am_tools->convert_am_error_to_eapol_error(error),
			complete_settings,
			error_completion_function));
	}

	error = CEapConversion::ConvertCertificatesToInternalType(
		m_am_tools,
		&aAvailableCACerts,
		&(complete_settings->m_Certificates));
	if (error != KErrNone)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, error_complete(
			m_am_tools->convert_am_error_to_eapol_error(error),
			complete_settings,
			error_completion_function));
	}

	complete_settings->m_CertificatesPresent = true;

	complete_settings->m_completion_status = eap_status_ok;
	complete_settings->m_EAPType = m_EAPType;
	complete_settings->m_IndexType = m_IndexType;
	complete_settings->m_Index = m_Index;

	eap_status_e status = m_partner->complete_get_certificate_lists(complete_settings);

	(void) EAP_STATUS_RETURN(m_am_tools, status);
	EAP_UNREFERENCED_PARAMETER(status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_general_settings_symbian_c::delete_all_eap_settings(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::delete_all_eap_settings(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::delete_all_eap_settings()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_general_settings_complete_delete_all_eap_settings);

	TInt error(KErrNone);

	TRAP(error, (OpenGeneralSettingsL()));

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::delete_all_eap_settings(): OpenGeneralSettingsL() failed, EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			error));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::delete_all_eap_settings(): this=0x%08x: DeleteGeneralSettingsDataL(): EAP-type=0xfe%06x%08x, index_type=%d, index=%d\n"),
		this,
		internal_settings->m_EAPType.get_vendor_id(),
		internal_settings->m_EAPType.get_vendor_type(),
		internal_settings->m_IndexType,
		internal_settings->m_Index));

	TRAP(error, (DeleteGeneralSettingsDataL(
		internal_settings->m_IndexType,
		internal_settings->m_Index)));
	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::delete_all_eap_settings(): EAP-type=0xfe%06x%08x, index_type=%d, index=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index));
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	{
		RPointerArray<TEapExpandedType> plugins_array;

		PointerArrayResetAndDestroy<TEapExpandedType> aAutomaticPlugins(&plugins_array, EFalse);

		EapPluginTools aPluginTool;

		TEapExpandedType aTunnelingType(*EapExpandedTypeNone.GetType());

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::delete_all_eap_settings(): this=0x%08x: aPluginTool.ListAllEapPluginsL(): tunneling EAP-type=0xfe%06x%08x, index_type=%d, index=%d\n"),
			this,
			aTunnelingType.GetVendorId(),
			aTunnelingType.GetVendorType(),
			internal_settings->m_IndexType,
			internal_settings->m_Index));

		// This will list all outer EAP-methods because aTunnelingType = None.
		TRAP(error, (aPluginTool.ListAllEapPluginsL(static_cast<TIndexType>(internal_settings->m_IndexType), aTunnelingType, plugins_array)));
		if (error != KErrNone)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: eap_am_general_settings_symbian_c::delete_all_eap_settings(): aPluginTool.ListAllEapPluginsL() failed, tunneling EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
				aTunnelingType.GetVendorId(),
				aTunnelingType.GetVendorType(),
				internal_settings->m_IndexType,
				internal_settings->m_Index,
				error));

			return EAP_STATUS_RETURN(
				m_am_tools,
				error_complete(
					m_am_tools->convert_am_error_to_eapol_error(error),
					internal_settings,
					error_completion_function));
		}

		TUint ind_outer(0ul);

		for (ind_outer = 0ul; ind_outer < plugins_array.Count(); ++ind_outer)
		{

			// List all plugins that could be used inside the each outer EAP-method on each plugin.

			RPointerArray<TEapExpandedType> tunneled_plugins;

			PointerArrayResetAndDestroy<TEapExpandedType> aAutomaticTunneledPlugins(&tunneled_plugins, EFalse);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_general_settings_symbian_c::delete_all_eap_settings(): this=0x%08x: aPluginTool.ListAllEapPluginsL(): tunneling EAP-type=0xfe%06x%08x, index_type=%d, index=%d\n"),
				this,
				plugins_array[ind_outer]->GetVendorId(),
				plugins_array[ind_outer]->GetVendorType(),
				internal_settings->m_IndexType,
				internal_settings->m_Index));

			// This will list all inner EAP-methods of EAP-type.
			TRAP(error, (aPluginTool.ListAllEapPluginsL(static_cast<TIndexType>(internal_settings->m_IndexType), plugins_array[ind_outer], tunneled_plugins)));
			if (error != KErrNone)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("ERROR: eap_am_general_settings_symbian_c::delete_all_eap_settings(): aPluginTool.ListAllEapPluginsL() failed, tunneling EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
					plugins_array[ind_outer]->GetVendorId(),
					plugins_array[ind_outer]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index,
					error));

				return EAP_STATUS_RETURN(
					m_am_tools,
					error_complete(
						m_am_tools->convert_am_error_to_eapol_error(error),
						internal_settings,
						error_completion_function));
			}


			// Delete possible configuration of each inner EAP-method that could be configured inside of outer EAP-method.

			TUint ind_inner(0ul);

			for (ind_inner = 0ul; ind_inner < tunneled_plugins.Count(); ++ind_inner)
			{
				CEapTypePlugin * eapType = NULL;

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::delete_all_eap_settings(): this=0x%08x: CEapTypePlugin::NewL(): EAP-type=0xfe%06x%08x, index_type=%d, index=%d\n"),
					this,
					tunneled_plugins[ind_inner]->GetVendorId(),
					tunneled_plugins[ind_inner]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index));

				TRAP(error, (eapType = CEapTypePlugin::NewL(
					tunneled_plugins[ind_inner]->GetValue(),
					static_cast<TIndexType>(internal_settings->m_IndexType),
					internal_settings->m_Index,
					m_am_tools)));

				// This will automatically delete eapType.
				eap_automatic_variable_c<CEapTypePlugin> automatic_eap_type(
					m_am_tools,
					eapType);

				if(error != KErrNone
					|| eapType == NULL)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_ERROR,
						(EAPL("ERROR: eap_am_general_settings_symbian_c::delete_all_eap_settings(): CEapTypePlugin::NewL() failed, EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
						tunneled_plugins[ind_inner]->GetVendorId(),
						tunneled_plugins[ind_inner]->GetVendorType(),
						internal_settings->m_IndexType,
						internal_settings->m_Index,
						error));

					return EAP_STATUS_RETURN(
						m_am_tools,
						error_complete(
							m_am_tools->convert_am_error_to_eapol_error(error),
							internal_settings,
							error_completion_function));
				}
				
			    eapType->SetTunnelingType(plugins_array[ind_outer]);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::delete_all_eap_settings(): this=0x%08x: eapType->DeleteConfigurationL(): EAP-type=0xfe%06x%08x, index_type=%d, index=%d\n"),
					this,
					tunneled_plugins[ind_inner]->GetVendorId(),
					tunneled_plugins[ind_inner]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index));

				TRAP(error, (eapType->DeleteConfigurationL()));
				if(error != KErrNone)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_ERROR,
						(EAPL("ERROR: eap_am_general_settings_symbian_c::delete_all_eap_settings(): eapType->DeleteConfigurationL() failed, EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
						tunneled_plugins[ind_inner]->GetVendorId(),
						tunneled_plugins[ind_inner]->GetVendorType(),
						internal_settings->m_IndexType,
						internal_settings->m_Index,
						error));

					return EAP_STATUS_RETURN(
						m_am_tools,
						error_complete(
							m_am_tools->convert_am_error_to_eapol_error(error),
							internal_settings,
							error_completion_function));
				}

			} // for()


			{

				// Delete possible configuration of each outer EAP-method on each plugin.

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::delete_all_eap_settings(): this=0x%08x: CEapTypePlugin::NewL(): outer EAP-type=0xfe%06x%08x, index_type=%d, index=%d\n"),
					this,
					plugins_array[ind_outer]->GetVendorId(),
					plugins_array[ind_outer]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index));

				CEapTypePlugin * eapType = NULL;

				TRAP(error, (eapType = CEapTypePlugin::NewL(
					plugins_array[ind_outer]->GetValue(),
					static_cast<TIndexType>(internal_settings->m_IndexType),
					internal_settings->m_Index,
					m_am_tools)));

				// This will automatically delete eapType.
				eap_automatic_variable_c<CEapTypePlugin> automatic_eap_type(
					m_am_tools,
					eapType);
				
				if(error != KErrNone
					|| eapType == NULL)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_ERROR,
						(EAPL("ERROR: eap_am_general_settings_symbian_c::delete_all_eap_settings(): CEapTypePlugin::NewL() failed, outer EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
						plugins_array[ind_outer]->GetVendorId(),
						plugins_array[ind_outer]->GetVendorType(),
						internal_settings->m_IndexType,
						internal_settings->m_Index,
						error));

					return EAP_STATUS_RETURN(
						m_am_tools,
						error_complete(
							m_am_tools->convert_am_error_to_eapol_error(error),
							internal_settings,
							error_completion_function));
				}
				
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::delete_all_eap_settings(): this=0x%08x: eapType->DeleteConfigurationL(): outer EAP-type=0xfe%06x%08x, index_type=%d, index=%d\n"),
					this,
					plugins_array[ind_outer]->GetVendorId(),
					plugins_array[ind_outer]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index));

				TRAP(error, (eapType->DeleteConfigurationL()));
				if(error != KErrNone)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_ERROR,
						(EAPL("ERROR: eap_am_general_settings_symbian_c::delete_all_eap_settings(): eapType->DeleteConfigurationL() failed, outer EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
						plugins_array[ind_outer]->GetVendorId(),
						plugins_array[ind_outer]->GetVendorType(),
						internal_settings->m_IndexType,
						internal_settings->m_Index,
						error));

					return EAP_STATUS_RETURN(
						m_am_tools,
						error_complete(
							m_am_tools->convert_am_error_to_eapol_error(error),
							internal_settings,
							error_completion_function));
				}
			}

		} // for()

	}

	complete_settings->m_completion_status = eap_status_ok;
	complete_settings->m_EAPType = internal_settings->m_EAPType;
	complete_settings->m_IndexType = internal_settings->m_IndexType;
	complete_settings->m_Index = internal_settings->m_Index;

	eap_status_e status = m_partner->complete_delete_all_eap_settings(complete_settings);

	iGeneralSettingsDb.Compact();

	CloseGeneralSettings();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::delete_all_eap_settings(): this=0x%08x, CloseGeneralSettings()\n"),
		this));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_general_settings_symbian_c::copy_all_eap_settings(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::copy_all_eap_settings(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_general_settings_symbian_c::copy_all_eap_settings()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_general_settings_complete_copy_all_eap_settings);

	TInt error(KErrNone);

	TRAP(error, (OpenGeneralSettingsL()));

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::copy_all_eap_settings(): OpenGeneralSettingsL() failed, EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			error));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	if (internal_settings == 0
		|| internal_settings->m_DestinationIndexAndTypePresent == false)
	{
		// Cannot copy without destination.
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_illegal_parameter,
				internal_settings,
				error_completion_function));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::copy_all_eap_settings(): this=0x%08x: DeleteGeneralSettingsDataL(): EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d\n"),
		this,
		internal_settings->m_EAPType.get_vendor_id(),
		internal_settings->m_EAPType.get_vendor_type(),
		internal_settings->m_IndexType,
		internal_settings->m_Index,
		internal_settings->m_DestinationIndexType,
		internal_settings->m_DestinationIndex));

	TRAP(error, (CopyGeneralSettingsDataL(
		internal_settings->m_IndexType,
		internal_settings->m_Index,
		internal_settings->m_DestinationIndexType,
		internal_settings->m_DestinationIndex)));
	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: eap_am_general_settings_symbian_c::copy_all_eap_settings(): EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d, error=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			internal_settings->m_DestinationIndexType,
			internal_settings->m_DestinationIndex,
			error));
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	{
		RPointerArray<TEapExpandedType> plugins;

		PointerArrayResetAndDestroy<TEapExpandedType> aAutomaticPlugins(&plugins, EFalse);

		EapPluginTools aPluginTool;

		TEapExpandedType aTunnelingType(*EapExpandedTypeNone.GetType());

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_general_settings_symbian_c::copy_all_eap_settings(): this=0x%08x: aPluginTool.ListAllEapPluginsL(): tunneling EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d\n"),
			this,
			aTunnelingType.GetVendorId(),
			aTunnelingType.GetVendorType(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			internal_settings->m_DestinationIndexType,
			internal_settings->m_DestinationIndex));

		// This will list all outer EAP-methods because aTunnelingType = None.
		TRAP(error, (aPluginTool.ListAllEapPluginsL(static_cast<TIndexType>(internal_settings->m_IndexType), aTunnelingType, plugins)));
		if (error != KErrNone)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: eap_am_general_settings_symbian_c::copy_all_eap_settings(): aPluginTool.ListAllEapPluginsL() failed, tunneling EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d, error=%d.\n"),
				aTunnelingType.GetVendorId(),
				aTunnelingType.GetVendorType(),
				internal_settings->m_IndexType,
				internal_settings->m_Index,
				internal_settings->m_DestinationIndexType,
				internal_settings->m_DestinationIndex,
				error));

			return EAP_STATUS_RETURN(
				m_am_tools,
				error_complete(
					m_am_tools->convert_am_error_to_eapol_error(error),
					internal_settings,
					error_completion_function));
		}

		TUint ind_outer(0ul);

		for (ind_outer = 0ul; ind_outer < plugins.Count(); ++ind_outer)
		{

			// List all plugins that could be used inside the each outer EAP-method on each plugin.

			RPointerArray<TEapExpandedType> tunneled_plugins;

			PointerArrayResetAndDestroy<TEapExpandedType> aAutomaticTunneledPlugins(&tunneled_plugins, EFalse);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_general_settings_symbian_c::copy_all_eap_settings(): this=0x%08x: aPluginTool.ListAllEapPluginsL(): tunneling EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d\n"),
				this,
				plugins[ind_outer]->GetVendorId(),
				plugins[ind_outer]->GetVendorType(),
				internal_settings->m_IndexType,
				internal_settings->m_Index,
				internal_settings->m_DestinationIndexType,
				internal_settings->m_DestinationIndex));

			// This will list all inner EAP-methods of EAP-type.
			TRAP(error, (aPluginTool.ListAllEapPluginsL(static_cast<TIndexType>(internal_settings->m_IndexType), plugins[ind_outer], tunneled_plugins)));
			if (error != KErrNone)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("ERROR: eap_am_general_settings_symbian_c::copy_all_eap_settings(): aPluginTool.ListAllEapPluginsL() failed, tunneling EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d, error=%d.\n"),
					plugins[ind_outer]->GetVendorId(),
					plugins[ind_outer]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index,
					internal_settings->m_DestinationIndexType,
					internal_settings->m_DestinationIndex,
					error));

				return EAP_STATUS_RETURN(
					m_am_tools,
					error_complete(
						m_am_tools->convert_am_error_to_eapol_error(error),
						internal_settings,
						error_completion_function));
			}


			// Copy possible configuration of each inner EAP-method that could be configured inside of outer EAP-method.

			TUint ind_inner(0ul);

			for (ind_inner = 0ul; ind_inner < tunneled_plugins.Count(); ++ind_inner)
			{
				CEapTypePlugin * eapType = NULL;

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::copy_all_eap_settings(): this=0x%08x: CEapTypePlugin::NewL(): EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d\n"),
					this,
					tunneled_plugins[ind_inner]->GetVendorId(),
					tunneled_plugins[ind_inner]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index,
					internal_settings->m_DestinationIndexType,
					internal_settings->m_DestinationIndex));

				TRAP(error, (eapType = CEapTypePlugin::NewL(
					tunneled_plugins[ind_inner]->GetValue(),
					static_cast<TIndexType>(internal_settings->m_IndexType),
					internal_settings->m_Index,
					m_am_tools)));

				// This will automatically delete eapType.
				eap_automatic_variable_c<CEapTypePlugin> automatic_eap_type(
					m_am_tools,
					eapType);

				if(error != KErrNone
					|| eapType == NULL)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_ERROR,
						(EAPL("ERROR: eap_am_general_settings_symbian_c::copy_all_eap_settings(): CEapTypePlugin::NewL() failed, EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d, error=%d.\n"),
						tunneled_plugins[ind_inner]->GetVendorId(),
						tunneled_plugins[ind_inner]->GetVendorType(),
						internal_settings->m_IndexType,
						internal_settings->m_Index,
						internal_settings->m_DestinationIndexType,
						internal_settings->m_DestinationIndex,
						error));

					return EAP_STATUS_RETURN(
						m_am_tools,
						error_complete(
							m_am_tools->convert_am_error_to_eapol_error(error),
							internal_settings,
							error_completion_function));
				}
				
			    eapType->SetTunnelingType(plugins[ind_outer]);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::copy_all_eap_settings(): this=0x%08x: eapType->CopySettingsL(): EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d\n"),
					this,
					tunneled_plugins[ind_inner]->GetVendorId(),
					tunneled_plugins[ind_inner]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index,
					internal_settings->m_DestinationIndexType,
					internal_settings->m_DestinationIndex));

				TRAP(error, (eapType->CopySettingsL(
					static_cast<TIndexType>(internal_settings->m_DestinationIndexType),
					internal_settings->m_DestinationIndex)));
				if(error != KErrNone)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_ERROR,
						(EAPL("ERROR: eap_am_general_settings_symbian_c::copy_all_eap_settings(): eapType->CopySettingsL() failed, EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d, error=%d.\n"),
						tunneled_plugins[ind_inner]->GetVendorId(),
						tunneled_plugins[ind_inner]->GetVendorType(),
						internal_settings->m_IndexType,
						internal_settings->m_Index,
						internal_settings->m_DestinationIndexType,
						internal_settings->m_DestinationIndex,
						error));

					return EAP_STATUS_RETURN(
						m_am_tools,
						error_complete(
							m_am_tools->convert_am_error_to_eapol_error(error),
							internal_settings,
							error_completion_function));
				}

			} // for()


			{

				// Copy possible configuration of each outer EAP-method on each plugin.

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::copy_all_eap_settings(): this=0x%08x: CEapTypePlugin::NewL(): outer EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d\n"),
					this,
					plugins[ind_outer]->GetVendorId(),
					plugins[ind_outer]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index,
					internal_settings->m_DestinationIndexType,
					internal_settings->m_DestinationIndex));

				CEapTypePlugin * eapType = NULL;

				TRAP(error, (eapType = CEapTypePlugin::NewL(
					plugins[ind_outer]->GetValue(),
					static_cast<TIndexType>(internal_settings->m_IndexType),
					internal_settings->m_Index,
					m_am_tools)));

				// This will automatically delete eapType.
				eap_automatic_variable_c<CEapTypePlugin> automatic_eap_type(
					m_am_tools,
					eapType);
				
				if(error != KErrNone
					|| eapType == NULL)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_ERROR,
						(EAPL("ERROR: eap_am_general_settings_symbian_c::copy_all_eap_settings(): CEapTypePlugin::NewL() failed, outer EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d, error=%d.\n"),
						plugins[ind_outer]->GetVendorId(),
						plugins[ind_outer]->GetVendorType(),
						internal_settings->m_IndexType,
						internal_settings->m_Index,
						internal_settings->m_DestinationIndexType,
						internal_settings->m_DestinationIndex,
						error));

					return EAP_STATUS_RETURN(
						m_am_tools,
						error_complete(
							m_am_tools->convert_am_error_to_eapol_error(error),
							internal_settings,
							error_completion_function));
				}
				
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_general_settings_symbian_c::copy_all_eap_settings(): this=0x%08x: eapType->CopySettingsL(): outer EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d\n"),
					this,
					plugins[ind_outer]->GetVendorId(),
					plugins[ind_outer]->GetVendorType(),
					internal_settings->m_IndexType,
					internal_settings->m_Index,
					internal_settings->m_DestinationIndexType,
					internal_settings->m_DestinationIndex));

				TRAP(error, (eapType->CopySettingsL(
					static_cast<TIndexType>(internal_settings->m_DestinationIndexType),
					internal_settings->m_DestinationIndex)));
				if(error != KErrNone)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_ERROR,
						(EAPL("ERROR: eap_am_general_settings_symbian_c::copy_all_eap_settings(): eapType->CopySettingsL() failed, outer EAP-type=0xfe%06x%08x, m_IndexType=%d, m_Index=%d, m_DestinationIndexType=%d, m_DestinationIndex=%d, error=%d.\n"),
						plugins[ind_outer]->GetVendorId(),
						plugins[ind_outer]->GetVendorType(),
						internal_settings->m_IndexType,
						internal_settings->m_Index,
						internal_settings->m_DestinationIndexType,
						internal_settings->m_DestinationIndex,
						error));

					return EAP_STATUS_RETURN(
						m_am_tools,
						error_complete(
							m_am_tools->convert_am_error_to_eapol_error(error),
							internal_settings,
							error_completion_function));
				}
			}

		} // for()

	}

	complete_settings->m_completion_status = eap_status_ok;
	complete_settings->m_EAPType = internal_settings->m_EAPType;
	complete_settings->m_IndexType = internal_settings->m_IndexType;
	complete_settings->m_Index = internal_settings->m_Index;

	eap_status_e status = m_partner->complete_copy_all_eap_settings(complete_settings);

	iGeneralSettingsDb.Compact();

	CloseGeneralSettings();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_general_settings_symbian_c::get_eap_methods(): this=0x%08x, CloseGeneralSettings()\n"),
		this));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------
// End
