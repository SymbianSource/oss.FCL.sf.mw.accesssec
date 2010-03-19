/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/wapi_core/symbian/certificate_store_db_symbian.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 61 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/


// INCLUDE FILES
#include <mmtsy_names.h>
#include <utf.h>                           // for CnvUtfConverter
#include <s32strm.h> 	                   // For RReadStream
#include <d32dbms.h>                       // for RDbColReadStream
#include "certificate_store_db_symbian.h"
#include "eap_am_trace_symbian.h"
#include "eap_variable_data.h"
#include "abs_eap_am_tools.h"
#include "eap_am_tools_symbian.h"
#include "eap_am_types.h"
#include "wapi_asn1_der_parser.h"
#include "wapi_am_core_symbian.h"
// ================= public:  Constructors and destructor =======================

// ---------------------------------------------------------
// CCertificateStoreDatabase::NewL()
// ---------------------------------------------------------
//
CCertificateStoreDatabase* CCertificateStoreDatabase::NewL(
    abs_eap_am_tools_c* aAmTools )
    {    
	CCertificateStoreDatabase* self = new(ELeave)
	    CCertificateStoreDatabase( aAmTools );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );

    return self;

    } // CCertificateStoreDatabase::NewL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::~CCertificateStoreDatabase()
// ---------------------------------------------------------
//
CCertificateStoreDatabase::~CCertificateStoreDatabase()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::~CCertificateStoreDatabase() IN\n" ) ) );

    Close();
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::~CCertificateStoreDatabase() OUT\n" ) ) );

    } // CCertificateStoreDatabase::~CCertificateStoreDatabase()


// ================= public: New, open/close/destroy functionality =======================


// ---------------------------------------------------------
// CCertificateStoreDatabase::OpenCertificateStoreL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::OpenCertificateStoreL()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::OpenCertificateStoreL() IN\n" ) ) );
	
    if ( iCsDbCreated == EFalse || iCsSessionOpened == EFalse )
		{
		// Certificate store DB and tables are not created.
		CreateCertificateStoreL();
		}

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::OpenCertificateStoreL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::OpenCertificateStoreL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::Close()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::Close()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::Close() IN\n" ) ) );

	if ( iCsDbCreated )
		{
		iCsDb.Close();
		iCsDbCreated = EFalse;
		}
	if ( iCsSessionOpened )
	    {
		iCsDbSession.Close();
		iCsSessionOpened = EFalse;
	    }	

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::Close() OUT\n" ) ) );
	
	} // CCertificateStoreDatabase::Close()

// ---------------------------------------------------------
// CCertificateStoreDatabase::SetCorePartner()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::SetCorePartner(wapi_am_core_symbian_c *partner)
    {
    iPartner = partner; 
    }

// ---------------------------------------------------------
// CCertificateStoreDatabase::DestroyCertificateStore()
// ---------------------------------------------------------
//
TInt CCertificateStoreDatabase::DestroyCertificateStore()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::DestroyCertificateStore() IN, \
        iCsSessionOpened=%d, iCsDbCreated=%d\n" ),
        iCsSessionOpened, iCsDbCreated ) );
		
    // There could be a case where certificate store DB is destroyed and UI
    // calls this function. We return KErrNone in that case.        
    if ( iCsDbCreated == EFalse )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "WARNING: CCertificateStoreDatabase::DestroyCertificateStore() \
            Certificate store DB doesn't exist. Returning KErrNone.\n" ) ) );
        return KErrNone;
        }

    if ( iCsSessionOpened == EFalse )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::DestroyCertificateStore() \
			Certificate store not opened!\n" ) ) );
		return KErrSessionClosed;
		}	
		
    if (iPartner != NULL)
        {
        iPartner->reset();
        }
    
	TInt error = iCsDb.Destroy();
		
	if ( error != KErrNone )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::DestroyCertificateStore() \
			iCsDb.Destroy() failed, error=%d.\n" ), error ) );
		}
		else
		{
		iCsDbCreated = EFalse;
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "CCertificateStoreDatabase::DestroyCertificateStore() \
			CS DB destroyed successfully.\n" ) ) );	
		}
	
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::DestroyCertificateStore() OUT,\
        error=%d.\n" ), error ) );
	
    return error;
	} // CCertificateStoreDatabase::DestroyCertificateStore()


// ================= public:  New =======================


// ---------------------------------------------------------
// CCertificateStoreDatabase::InitializeCertificateStoreL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::InitializeCertificateStoreL()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InitializeCertificateStoreL() IN\n" ) ) );

    WriteCertificateStoreStateL( ECertificateStoreInitialized );
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InitializeCertificateStoreL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::InitializeCertificateStoreL()


// ================= public: New, get/set/remove data in database =======================


// ---------------------------------------------------------
// CCertificateStoreDatabase::GetCsDataByReferenceL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::GetCsDataByReferenceL(
    ec_cs_data_type_e aDataType,
    const TDesC8& aDataReference,
   	HBufC8** aOutColumnValue )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataByReferenceL1() IN\n" ) ) );
    
        // Convert the received reference id into integer.. 
    TUint intRef;
    if (aDataType != ec_cs_data_type_selected_ca_id && aDataType != ec_cs_data_type_selected_client_id)
        {
        // Convert the received reference id into integer.. 
        intRef = eap_read_u32_t_network_order(
            aDataReference.Ptr(),
            aDataReference.Size());
        }
    else
        {
        intRef = static_cast<TUint>(*aDataReference.Ptr());
        }
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ( "CCertificateStoreDatabase::GetCsDataByReference1L() \
            New entry: reference set to DB(TEXT)=%d\n" ), intRef ) );
    GetCsDataByReferenceL ( aDataType, intRef, aOutColumnValue );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataByReferenceL1() OUT\n" ) ) );

	} // CCertificateStoreDatabase::GetCsDataByReferenceL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::GetCsDataByReferenceL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::GetCsDataByReferenceL(
    ec_cs_data_type_e aDataType,
    const TUint aDataReference,
   	HBufC8** aOutColumnValue )
    
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataByReferenceL() IN\n" ) ) );
    	
    // There could be a case where CS DB is destroyed and UI
    // calls this function. We just return in that case.
    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "ERROR: CCertificateStoreDatabase::GetCsDataByReferenceL() \
                CS DB doesn't exist. Don't do anything.\n" ) ) );
        return;
        }

    if ( !iCsSessionOpened )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "ERROR: CCertificateStoreDatabase::GetCsDataByReferenceL() - CS not opened.\n" ) ) );
        User::Leave( KErrSessionClosed );
        }			
		    
    // DB names
    TBuf<KDbMaxName> tableName;               // const from d32dbms.h
    TBuf<KDbMaxColName> referenceColumnName;  // const from d32dbms.h
    TBuf<KDbMaxColName> dataColumnName;       // const from d32dbms.h

    GetDbNamesFromDataTypeL( aDataType, tableName, referenceColumnName,
		                        dataColumnName );

    // create SQL query statement
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();

    _LIT( KSqlQuery, "SELECT %S FROM %S WHERE %S=%d" );
    sqlStatement.Format( KSqlQuery, &dataColumnName, &tableName, &referenceColumnName, aDataReference );

    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
            "wapi_am_core_symbian_c::GetCsDataByReferenceL() sqlStatement",
            sqlStatement.Ptr(), sqlStatement.Size() ) );	

    RDbView view;
    User::LeaveIfError( view.Prepare( iCsDb, TDbQuery( sqlStatement ),
            TDbWindow::EUnlimited, RDbView::EReadOnly ) );
    

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataByReferenceL() View prepared OK.\n" ) ) );
	CleanupClosePushL( view );
	User::LeaveIfError( view.EvaluateAll() );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataByReferenceL() View evaluated OK.\n" ) ) );    
    
	if ( view.FirstL() )
	    {
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "CCertificateStoreDatabase::GetCsDataByReferenceL() view.FirstL() OK.\n" ) ) );    
		
		view.GetL();		
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "CCertificateStoreDatabase::GetCsDataByReferenceL() view.GetL() OK.\n" ) ) );    

		switch ( view.ColType( KDefaultColumnNumberOne ) )
		    {
		    case EDbColText:				
			    {
                // Buffer for unicode parameter
                HBufC* unicodebuf = HBufC::NewLC(view.ColLength( KDefaultColumnNumberOne ));
                TPtr unicodeString = unicodebuf->Des();
                unicodeString = view.ColDes(KDefaultColumnNumberOne);
                // Convert to 8-bit
                if (unicodeString.Size() > 0)
                    {
                    *aOutColumnValue = HBufC8::NewLC(
                        view.ColLength( KDefaultColumnNumberOne ) ); // Buffer for the data.
                    TPtr8 outColumnValuePtr8 = ( *aOutColumnValue )->Des();
                    outColumnValuePtr8.Copy(unicodeString);
                    if (outColumnValuePtr8.Size() == 0)
	                    {
	                        User::Leave(KErrNoMemory);
	                    }
                    CleanupStack::Pop( *aOutColumnValue );
                    } 
                else 
                    {
                        // Empty field. Do nothing...data remains invalid
                    }
                CleanupStack::PopAndDestroy(unicodebuf);
			    break;
			    }
			    
		    case EDbColUint32:
	            {
	                TUint value;
	                value = view.ColUint32(KDefaultColumnNumberOne);
                    *aOutColumnValue = HBufC8::NewLC(
                        view.ColLength( KDefaultColumnNumberOne ) ); // Buffer for the data.
                    TPtr8 outColumnValuePtr8 = ( *aOutColumnValue )->Des();
                    outColumnValuePtr8.Copy((const unsigned char *)&value, sizeof(TUint));
                    if (outColumnValuePtr8.Size() == 0)
                    {
                        User::Leave(KErrNoMemory);
                    }
                    CleanupStack::Pop( *aOutColumnValue );
	            }
	            break;
		        
		    case EDbColBinary:
			    {
		        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	                "ERROR: CCertificateStoreDatabase::GetCsDataByReferenceL() \
	                Unsupported DB field EDbColBinary.\n" ) ) );
				User::Leave( KErrNotSupported );
                break;
			    }
		    case EDbColLongBinary:				
			    {
		        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
					"CCertificateStoreDatabase::GetCsDataByReferenceL() \
					Long binary column.\n" ) ) );			
				GetLongBinaryDataL( view, aOutColumnValue );
				break;
			    }			
		    default:
		    	{
		        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		            "ERROR: CCertificateStoreDatabase::GetCsDataByReferenceL() \
		            Unsupported DB field:%d\n" ), 
		            view.ColType( KDefaultColumnNumberOne ) ) );
			    User::Leave( KErrNotSupported );
			    break;
		    	}
		    } // switch ( view.ColType( KDefaultColumnNumberOne ) )
	    } // if ( view.FirstL() )
	
	// clean
	CleanupStack::PopAndDestroy( &view ); // Close view.	
    CleanupStack::PopAndDestroy( buf );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataByReferenceL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::GetCsDataByReferenceL()
	

// ---------------------------------------------------------
// CCertificateStoreDatabase::GetCsDataL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::GetCsDataL(
	ec_cs_data_type_e aDataType,
    HBufC8** aOutColumnValue,
	RArray<SWapiCertEntry>& aArray,
	TBool aGetAll)

	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataL() IN\n" ) ) );

    aArray.Reset();
    
    // There could be a case where CS DB is destroyed and UI
    // calls this function. We just return in that case.
    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::GetCsDataL() \
            CS DB doesn't exist. Don't do anything.\n" ) ) );
        return;
        }

    if ( !iCsSessionOpened )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::GetCsDataL() CS not opened.\n" ) ) );
		User::Leave( KErrSessionClosed );
		}			

    // DB names
	TBuf<KDbMaxName> tableName;               // const from d32dbms.h
	TBuf<KDbMaxColName> dataColumnName;       // const from d32dbms.h

	GetDbNamesFromDataTypeL( aDataType, tableName, dataColumnName );

  	// create SQL query statement
	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();

	_LIT( KSqlQuery, "SELECT %S FROM %S" );
    _LIT( KSqlQueryAll, "SELECT * FROM %S" );
	if (aGetAll)
	    sqlStatement.Format( KSqlQueryAll, &tableName );
	else
	    sqlStatement.Format( KSqlQuery, &dataColumnName, &tableName );
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::GetCsDataL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );	

		
 	RDbView view;
	User::LeaveIfError( view.Prepare( iCsDb, TDbQuery( sqlStatement ),
		TDbWindow::EUnlimited, RDbView::EReadOnly ) );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataL() View prepared OK.\n" ) ) );
	CleanupClosePushL( view );
	User::LeaveIfError( view.EvaluateAll() );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataL() View evaluated OK.\n" ) ) );    
    
 	if ( view.FirstL() && aGetAll == EFalse)
	    {
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"CCertificateStoreDatabase::GetCsDataL() view.FirstL() OK.\n" ) ) );
		
		view.GetL();		
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"CCertificateStoreDatabase::GetCsDataL() view.GetL() OK.\n" ) ) );

		switch ( view.ColType( KDefaultColumnNumberOne ) )
		    {
		    case EDbColText:				
			    {
                EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                    "CCertificateStoreDatabase::GetCsDataL() \
                    EDbColText.\n" ) ) );            
			    // Buffer for unicode parameter
                HBufC* unicodebuf = HBufC::NewLC(view.ColLength( KDefaultColumnNumberOne ));
			    TPtr unicodeString = unicodebuf->Des();
                unicodeString = view.ColDes(KDefaultColumnNumberOne);
                // Convert to 8-bit
                if (unicodeString.Size() > 0)
                    {
                    *aOutColumnValue = HBufC8::NewLC(
                        view.ColLength( KDefaultColumnNumberOne ) ); // Buffer for the data.
                    TPtr8 outColumnValuePtr8 = ( *aOutColumnValue )->Des();
                    outColumnValuePtr8.Copy(unicodeString);
                     if (outColumnValuePtr8.Size() == 0)
                    {
                        User::Leave(KErrNoMemory);
                    }
                     CleanupStack::Pop( *aOutColumnValue );

                } 
                else 
                    {
                        // Empty field. Do nothing...data remains invalid
                     }
                CleanupStack::PopAndDestroy(unicodebuf);

                break;
			    }
	         case EDbColUint32:
	                {
	                EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	                    "CCertificateStoreDatabase::GetCsDataL() \
	                    EDbColUint32.\n" ) ) );            
	                    TUint value;
	                    value = view.ColUint32(KDefaultColumnNumberOne);
	                    *aOutColumnValue = HBufC8::NewLC(
	                        view.ColLength( KDefaultColumnNumberOne ) ); // Buffer for the data.
	                    TPtr8 outColumnValuePtr8 = ( *aOutColumnValue )->Des();
	                    outColumnValuePtr8.Copy((const unsigned char *)&value, sizeof(TUint));
	                    if (outColumnValuePtr8.Size() == 0)
	                    {
	                        User::Leave(KErrNoMemory);
	                    }
	                    CleanupStack::Pop( *aOutColumnValue );
	                    if (outColumnValuePtr8.Size() == 0)
	                    {
	                        User::Leave(KErrNoMemory);
	                    }
	                }
	                break;

		    case EDbColBinary:
			    {
		        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
					"CCertificateStoreDatabase::GetCsDataL() \
					Binary column.\n" ) ) );			
				GetBinaryDataL( view, aOutColumnValue );
                break;
			    }
		    case EDbColLongBinary:				
			    {
                EAP_TRACE_DEBUG_SYMBIAN(
                    (_L("CCertificateStoreDatabase::GetCsDataL - Long Binary column\n")));
            
                GetLongBinaryDataL( view, aOutColumnValue );
                break;
			    }			
		    default:
		    	{
		        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			    	"ERROR: CCertificateStoreDatabase::GetCsDataL() \
			    	Unsupported DB field:%d\n" ),
				    view.ColType( KDefaultColumnNumberOne ) ) );	
			    User::Leave( KErrNotSupported );
			    break;
		    	}
		    } // switch ( view.ColType( KDefaultColumnNumberOne ) )
	    } // if ( view.FirstL() )
 	else
        {
        if (view.FirstL())
            {
            GetTableDataL(view, aArray);       
            }
        }
	// clean memory
	CleanupStack::PopAndDestroy( &view );
    CleanupStack::PopAndDestroy( buf );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCsDataL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::GetCsDataL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::SetCsDataByReferenceL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::SetCsDataByReferenceL(
    ec_cs_data_type_e aDataType,
	const TDesC8& aColumnValue,
	const TDesC8& aDataReference,
	const TBool aIsNewEntry )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataByReferenceL1() IN\n" ) ) );
	
    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
        "wapi_am_core_symbian_c::SetCsDataByReferenceL1() Reference",
        aDataReference.Ptr(), 
        aDataReference.Size() ) );
    
	  // Convert the received reference id into integer.. 
    TUint intRef = eap_read_u32_t_network_order(
            aDataReference.Ptr(),
            aDataReference.Size());
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ( "CCertificateStoreDatabase::SetCsDataByReferenceL1() \
            New entry: reference set to DB(TEXT)=%d\n" ), intRef ) );
    SetCsDataByReferenceL ( aDataType, aColumnValue, intRef, aIsNewEntry );
		
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataByReferenceL1() OUT\n" ) ) );

	} // CCertificateStoreDatabase::SetCsDataByReferenceL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::SetCsDataByReferenceL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::SetCsDataByReferenceL(
    ec_cs_data_type_e aDataType,
    const TDesC8& aColumnValue,
    const TUint aDataReference,
    const TBool aIsNewEntry )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataByReferenceL() IN\n" ) ) );
    
    // There could be a case where CS DB is destroyed and UI
    // calls this function. We just return in that case.
    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::SetCsDataByReferenceL() \
            CS DB doesn't exist. Don't do anything.\n" ) ) );
        return;
        }
    
    if ( !iCsSessionOpened )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::SetCsDataByReferenceL() \
            CS not opened.\n" ) ) );
        User::Leave( KErrSessionClosed );
        }           
    
    if ( aColumnValue.Size() <= 0 )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::SetCsDataByReferenceL() \
            Column value is negative!\n" ) ) );
        User::Leave( KErrArgument );
        }
    
    // DB names
    TBuf<KDbMaxName> tableName;               // const from d32dbms.h
    TBuf<KDbMaxColName> referenceColumnName;  // const from d32dbms.h
    TBuf<KDbMaxColName> dataColumnName;       // const from d32dbms.h
    RDbView::TAccess dbMode = RDbView::EUpdatable;       
    
    GetDbNamesFromDataTypeL( aDataType, tableName, referenceColumnName, 
                            dataColumnName );

    // create SQL query statement
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();
    
    _LIT( KSqlQueryInsert, "SELECT * FROM %S" );
    _LIT( KSqlQueryWithRef, "SELECT %S FROM %S WHERE %S=%d" );

    if( aIsNewEntry )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "CCertificateStoreDatabase::SetCsDataByReferenceL() \
             New Entry.\n" ) ) );
       dbMode = RDbView::EInsertOnly;         
        sqlStatement.Format( KSqlQueryInsert, &tableName );         
        }
    else
        {
        sqlStatement.Format( KSqlQueryWithRef,
                             &dataColumnName,
                             &tableName,
                             &referenceColumnName,
                             &aDataReference );
        }

    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
        "wapi_am_core_symbian_c::SetCsDataByReferenceL() sqlStatement",
        sqlStatement.Ptr(), 
        sqlStatement.Size() ) );        
    
     RDbView view;   
    User::LeaveIfError( view.Prepare( iCsDb, TDbQuery( sqlStatement ),
        TDbWindow::EUnlimited, dbMode ) );   
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataByReferenceL() \
        View prepared OK.\n" ) ) );
    
    CleanupClosePushL( view );
    User::LeaveIfError( view.EvaluateAll() );
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataByReferenceL() \
        View evaluated OK.\n" ) ) );

    if ( aIsNewEntry && ( aDataReference > 0 ) )
        {       
        InsertDataAndReferenceL( view, referenceColumnName,
            dataColumnName, aDataReference, aColumnValue );     
        } // if ( aIsNewEntry && ...
    else
        {
        UpdateColOneRowOneL( view, aColumnValue );      
        }

    view.PutL();    
    
    // clean
    CleanupStack::PopAndDestroy( &view );   
    CleanupStack::PopAndDestroy( buf );
        
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataByReferenceL() OUT\n" ) ) );

    } // CCertificateStoreDatabase::SetCsDataByReferenceL()
    
    

// ---------------------------------------------------------
// CCertificateStoreDatabase::SetCsDataL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::SetCsDataL(
    ec_cs_data_type_e aDataType,
	const TDesC8& aColumnValue,
	const TBool aIsNewEntry )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataL() IN\n" ) ) );
    
    // There could be a case where CS DB is destroyed and UI
    // calls this function. We just return in that case.
    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::SetCsDataL() \
            CS DB doesn't exist. Don't do anything.\n" ) ) );
        return;
        }

    if ( !iCsSessionOpened )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::SetCsDataL() \
            CS not opened.\n" ) ) );
		User::Leave( KErrSessionClosed );
		}			

	if ( aColumnValue.Size() <= 0 )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"ERROR: CCertificateStoreDatabase::SetCsDataL() \
			Column value is empty!\n" ) ) );
		User::Leave( KErrArgument );
		}

    // DB names
	TBuf<KDbMaxName> tableName;               // const from d32dbms.h
	TBuf<KDbMaxColName> dataColumnName;       // const from d32dbms.h
	RDbView::TAccess dbMode = RDbView::EUpdatable;		
	
	GetDbNamesFromDataTypeL( aDataType, tableName, dataColumnName );

	// create SQL query statement
	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();
	
	_LIT( KSqlQuery, "SELECT %S FROM %S" );
	_LIT( KSqlQueryInsert, "SELECT * FROM %S" );

	if( aIsNewEntry )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	        "CCertificateStoreDatabase::SetCsDataByReferenceL() \
	        New Entry.\n" ) ) );
		dbMode = RDbView::EInsertOnly;			
		sqlStatement.Format( KSqlQueryInsert, &tableName );			
		}
	else
		{
		sqlStatement.Format( KSqlQuery,
			                 &dataColumnName,
			                 &tableName );
		}

	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::SetCsDataL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );	
	
	RDbView view;	
	User::LeaveIfError( view.Prepare( iCsDb, TDbQuery( sqlStatement ),
		TDbWindow::EUnlimited, dbMode ) );   
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataByReferenceL() \
        View prepared OK.\n" ) ) );
	CleanupClosePushL( view );
	User::LeaveIfError( view.EvaluateAll() );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataByReferenceL() \
        View evaluated OK.\n" ) ) );
	
	if ( aIsNewEntry )
		{
		InsertDataL( view, dataColumnName, aColumnValue );		
	    }
	else
	    {
	    UpdateColOneRowOneL( view, aColumnValue );		
	    }
	
	view.PutL();	
	
	// clean
	CleanupStack::PopAndDestroy( &view );	
	CleanupStack::PopAndDestroy( buf );
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::SetCsDataL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::SetCsDataL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::RemoveCsDataByReferenceL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::RemoveCsDataByReferenceL(
	ec_cs_data_type_e aDataType,
    const TDesC8& aColumnValue,
    const TDesC8& aDataReference )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::RemoveCsDataByReferenceL1() IN\n" ) ) );

    // Convert the received reference id into integer.. 
    TUint intRef = eap_read_u32_t_network_order(
            aDataReference.Ptr(),
            aDataReference.Size());
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ( "CCertificateStoreDatabase::RemoveCsDataByReferenceL1() \
            New entry: reference set to DB(TEXT)=%d\n" ), intRef ) );

    RemoveCsDataByReferenceL ( aDataType, aColumnValue, intRef );
		
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "CCertificateStoreDatabase::RemoveCsDataByReferenceL1() OUT\n" ) ) );

	} // CCertificateStoreDatabase::RemoveCsDataByReferenceL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::RemoveCsDataByReferenceL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::RemoveCsDataByReferenceL(
    ec_cs_data_type_e aDataType,
    const TDesC8& aColumnValue,
    const TUint aDataReference )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::RemoveCsDataByReferenceL() IN\n" ) ) );
    
    // There could be a case where CS DB is destroyed and UI
    // calls this function. We just return in that case.
    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::RemoveCsDataByReferenceL() \
            CS DB doesn't exist. Don't do anything.\n" ) ) );
        return;
        }

    if ( !iCsSessionOpened )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::RemoveCsDataByReferenceL() \
            CS not opened.\n" ) ) );
        User::Leave( KErrSessionClosed );
        }           

    if ( aColumnValue.Size() <= 0 )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::RemoveCsDataByReferenceL() \
            Column value is empty!\n" ) ) );
        User::Leave( KErrArgument );
        }
        
    // DB names
    TBuf<KDbMaxName> tableName;               // const from d32dbms.h
    TBuf<KDbMaxColName> referenceColumnName;  // const from d32dbms.h
    TBuf<KDbMaxColName> dataColumnName;       // const from d32dbms.h
    RDbView::TAccess dbMode = RDbView::EUpdatable;      
    
    GetDbNamesFromDataTypeL( aDataType, tableName, referenceColumnName,
        dataColumnName );
    
    // create SQL query statement
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();
    
    _LIT( KSqlQueryWithRef, "SELECT %S FROM %S WHERE %S=%d" );  
    sqlStatement.Format( KSqlQueryWithRef,
                         &dataColumnName,
                         &tableName,
                         &referenceColumnName,
                         &aDataReference );
    
    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
        "wapi_am_core_symbian_c::RemoveCsDataByReferenceL() sqlStatement",
        sqlStatement.Ptr(), 
        sqlStatement.Size() ) );        
    
    RDbView view;   
    User::LeaveIfError( view.Prepare( iCsDb, TDbQuery( sqlStatement ),
        TDbWindow::EUnlimited, dbMode ) );   
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::RemoveCsDataByReferenceL() \
        View prepared OK.\n" ) ) );
    CleanupClosePushL( view );
    User::LeaveIfError( view.EvaluateAll() );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::RemoveCsDataByReferenceL() \
        View evaluated OK.\n" ) ) );
        
    if ( view.FirstL() )
        {
        view.DeleteL();
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "CCertificateStoreDatabase::RemoveCsDataByReferenceL() \
            View deleted OK.\n" ) ) );
        }
    else
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "CCertificateStoreDatabase::RemoveCsDataByReferenceL() \
            No data found.\n" ) ) );
        }
    
    // clean
    CleanupStack::PopAndDestroy( &view );
    CleanupStack::PopAndDestroy( buf );
        
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::RemoveCsDataByReferenceL() OUT\n" ) ) );

    } // CCertificateStoreDatabase::RemoveCsDataByReferenceL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::RemoveCsDataL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::RemoveCsDataL(
	ec_cs_data_type_e aDataType,
    const TDesC8& aColumnValue )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::RemoveCsDataL() IN\n" ) ) );

    // There could be a case where CS DB is destroyed and UI
    // calls this function. We just return in that case.
    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::RemoveCsDataL() \
            CS DB doesn't exist. Don't do anything.\n" ) ) );
        return;
        }

    if ( !iCsSessionOpened )
	    {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::RemoveCsDataL() \
            CS not opened.\n" ) ) );
	    User::Leave( KErrSessionClosed );
	    }			

    if ( aColumnValue.Size() <= 0 )
	    {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		    "ERROR: CCertificateStoreDatabase::RemoveCsDataL() \
		    Column value is empty!\n" ) ) );
	    User::Leave( KErrArgument );
	    }
	    
	// DB names
	TBuf<KDbMaxName> tableName;               // const from d32dbms.h
	TBuf<KDbMaxColName> referenceColumnName;  // const from d32dbms.h
	TBuf<KDbMaxColName> dataColumnName;       // const from d32dbms.h
	RDbView::TAccess dbMode = RDbView::EUpdatable;	
	
	GetDbNamesFromDataTypeL( aDataType, tableName, referenceColumnName,
		dataColumnName );
	
	// create SQL query statement
	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();
	
	_LIT( KSqlQuery, "SELECT %S FROM %S" );
	sqlStatement.Format( KSqlQuery,
		                 &dataColumnName,
		                 &tableName );
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::RemoveCsDataL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );		
	
	RDbView view;	
	User::LeaveIfError( view.Prepare( iCsDb, TDbQuery( sqlStatement ),
		TDbWindow::EUnlimited, dbMode ) );   
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "CCertificateStoreDatabase::RemoveCsDataL() \
	    View prepared OK.\n" ) ) );
	CleanupClosePushL( view );
	User::LeaveIfError( view.EvaluateAll() );
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "CCertificateStoreDatabase::RemoveCsDataL() \
	    View evaluated OK.\n" ) ) );
		
	if ( view.FirstL() )
		{
		view.DeleteL();
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	        "CCertificateStoreDatabase::RemoveCsDataL() \
			View deleted OK.\n" ) ) );
		}
	else
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	        "CCertificateStoreDatabase::RemoveCsDataL() \
            No data found.\n" ) ) );
		}
	
	// clean
	CleanupStack::PopAndDestroy( &view );	
	CleanupStack::PopAndDestroy( buf );
		
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "CCertificateStoreDatabase::RemoveCsDataL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::RemoveCsDataL()


// ================= public: New, boolean conditions =======================


// ---------------------------------------------------------
// CCertificateStoreDatabase::IsInitializedL()
// ---------------------------------------------------------
//
TBool CCertificateStoreDatabase::IsInitializedL()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::IsInitializedL() IN\n" ) ) );
		
    // There could be a case where CS DB is destroyed and UI
    // calls this function. We return EFalse in that case.      
    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "CCertificateStoreDatabase::IsInitializedL() \
            Certificate store DB doesn't exist. Returning EFalse." ) ) );   
        return EFalse;
        }

    if ( !iCsSessionOpened )
	    {
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"CCertificateStoreDatabase::IsInitializedL() \
			ERROR: certificate store not opened!" ) ) );
		return EFalse;
		}	
		
	TBool IsInitializedL( EFalse );		
				
	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();

	// Query only initialization flag field from general settings table.
	_LIT( KSqlQuery, "SELECT %S FROM %S" );
	sqlStatement.Format( KSqlQuery,
						 &KCsInitialized,
						 &KCsGeneralSettingsTableName );

	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::IsInitializedL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );	

	RDbView view;		
	User::LeaveIfError( view.Prepare( iCsDb, TDbQuery( sqlStatement ),
		TDbWindow::EUnlimited, RDbView::EReadOnly ) );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::IsInitializedL() View prepared OK.\n" ) ) );
	
	CleanupStack::PopAndDestroy( buf );
	
	CleanupClosePushL( view );
		
	User::LeaveIfError( view.EvaluateAll() );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::IsInitializedL() View evaluated OK.\n" ) ) );    
	
	if ( view.FirstL() )
	    {
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		    "CCertificateStoreDatabase::IsInitializedL() view.FirstL() OK.\n" ) ) );
		view.GetL();
		
		if ( view.IsColNull( KDefaultColumnNumberOne ) )
			{
			IsInitializedL = EFalse;
			}
		else
			{
			// Store the line
			TUint initValue = view.ColUint( KDefaultColumnNumberOne );
			
			if ( initValue == ECertificateStoreInitialized )
				{
				IsInitializedL = ETrue;
				}
			else
				{
				IsInitializedL = EFalse;
				}
			
			}		
		}
	else
	    {
		// Nothing in the view means there is no entry at all.
		IsInitializedL = EFalse;
		}
	
	CleanupStack::PopAndDestroy( &view ); // Close view.		

	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"CCertificateStoreDatabase::IsInitializedL() \
		OUT, IsInitializedL=%d.\n" ), IsInitializedL ) );
	
	return IsInitializedL;	
	} // CCertificateStoreDatabase::IsInitializedL()


// ================= private: Access =======================


// ---------------------------------------------------------
// CCertificateStoreDatabase::GetCertificateStoreDb()
// ---------------------------------------------------------
//
RDbNamedDatabase& CCertificateStoreDatabase::GetCertificateStoreDb()
    {
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCertificateStoreDb() IN\n" ) ) );

	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetCertificateStoreDb() OUT\n" ) ) );
	return iCsDb; 
    }


// ================= private: New, database, tables =======================


// ---------------------------------------------------------
// CCertificateStoreDatabase::CreateCertificateStoreL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreateCertificateStoreL()
    {
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateCertificateStoreL() IN\n" ) ) );

    // 1. Open/create a database	
    CreateDatabaseL();

    // 2. Create CS tables to database (ignore error if tables exist)	

    // Table 1: Create table for general settings. 
    CreateGeneralSettingsTableL();

    // Table 2: Create table for client ASU-ID list
    CreateClientAsuIdListTableL();

    // Table 3: Create table for CA ASU-ID list
    CreateCaAsuIdListTableL();

    // Table 4: Create table for client certificates
    CreateClientCertificateTableL();

    // Table 5: Create table for CA certificates
    CreateCaCertificateTableL();

    // Table 6: Create table for private keys
    CreatePrivateKeyTableL();

    // Table 7: Create table for WAPI certificate labels
    CreateWapiCertLabeltableL();

    // Table 8: Create table for WAPI certificate files
    CreateWapiCertFiletableL();

    
    iCsDbCreated = ETrue;
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateCertificateStoreL() OUT\n" ) ) );    
    
    } // CCertificateStoreDatabase::CreateCertificateStoreL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::CreateDatabaseL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreateDatabaseL()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateDatabaseL() IN\n" ) ) );    

	// Connect to the DBMS server, if not connected already.
	if ( !iCsSessionOpened )
	    {
		User::LeaveIfError( iCsDbSession.Connect() );
		iCsSessionOpened = ETrue;
	    }		
	
	// Create the secure shared database with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).
	TInt err = iCsDb.Create( iCsDbSession, KCsDatabaseName,
		KSecureUidFormatCertificate );
	DEBUG1( "CCertificateStoreDatabase::CreateDatabaseL() Created secure DB for \
		certificatestore.dat, err=%d (-11=DB already exist).", err );	
	if ( err == KErrNone )
	    {
		iCsDb.Close();
	    }
	else if ( err != KErrAlreadyExists ) 
	    {
		User::LeaveIfError( err );
	    }
	User::LeaveIfError( iCsDb.Open( iCsDbSession, KCsDatabaseName,
		KSecureUidFormatCertificate ) );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateDatabaseL() OUT\n" ) ) );    
	
	} // CCertificateStoreDatabase::CreateDatabaseL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::CreateGeneralSettingsTableL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreateGeneralSettingsTableL()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateGeneralSettingsTableL() IN\n" ) ) );

    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();

    // Table columns:
    ////// NAME //////////////////////////// TYPE ////////////// Constant ////////////////////////
    //| CS_password						     | VARBINARY(255)	| KCsPassword                  |//
    //| CS_reference_counter			     | VARBINARY(255)	| KCsReferenceCounter	   	   |//
    //| CS_master_key					     | VARBINARY(255)	| KCsMasterKey	   	           |//
    //| CS_initialized					     | UNSIGNED INTEGER | KCsInitialized	   	       |//
    //| CS_password_max_validity_time        | BIGINT	   	    | KCsPasswordMaxValidityTime   |//
    //| CS_password_last_identity_time	     | BIGINT	   		| KCsLastPasswordIdentityTime  |//	    
    //////////////////////////////////////////////////////////////////////////////////////////////

    _LIT( KSqlCreateTable, "CREATE TABLE %S (\
	    %S VARBINARY(%d),     \
	    %S VARBINARY(%d),	  \
        %S VARBINARY(%d),	  \
	    %S UNSIGNED INTEGER,  \
	    %S BIGINT,            \
	    %S BIGINT)" );
									 
    sqlStatement.Format(
        KSqlCreateTable, &KCsGeneralSettingsTableName,
        &KCsPassword, KCsMaxPasswordLengthInDb,
        &KCsReferenceCounter, KCsMaxRefCounterLengthInDb,
        &KCsMasterKey, KCsMaxMasterKeyLengthInDb,
        &KCsInitialized,
        &KCsPasswordMaxValidityTime,
        &KCsLastPasswordIdentityTime,
        &KCsPrivateKeyAsuIdReference);
    
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::CreateGeneralSettingsTableL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );

    TInt err = iCsDb.Execute( sqlStatement );
    if ( err != KErrNone && err != KErrAlreadyExists )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::CreateGeneralSettingsTableL() \
            iCsDb.Execute(), err=%d.\n" ), err ) );
        CleanupStack::PopAndDestroy( buf );
        User::Leave( err );
        }
    CleanupStack::PopAndDestroy( buf );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateGeneralSettingsTableL() OUT\n" ) ) );
    
	} // CCertificateStoreDatabase::CreateGeneralSettingsTableL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::CreateClientAsuIdListTableL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreateClientAsuIdListTableL()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateClientAsuIdListTableL() IN\n" ) ) );

    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();

    // Table columns:
    ////// NAME /////////////////////// TYPE ///////////// Constant ////////////////////
    //| CS_client_ASU_ID_reference    | UNSIGNED INTEGER   | KCsClientAsuIdReference |//		
    //| CS_client_ASU_ID_data         | LONG VARBINARY	   | KCsClientAsuIdData      |//	
    ////////////////////////////////////////////////////////////////////////////////////
    _LIT( KSqlCreateTable, "CREATE TABLE %S (\
    	%S UNSIGNED INTEGER, \
        %S LONG VARBINARY)" );

    sqlStatement.Format( KSqlCreateTable, &KCsClientAsuIdListTableName, 
    	&KCsClientAsuIdReference, &KCsClientAsuIdData );
    
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::CreateClientAsuIdListTableL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );
    
    TInt err = iCsDb.Execute( sqlStatement );
    if ( err != KErrNone && err != KErrAlreadyExists )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::CreateClientAsuIdListTableL() \
            iCsDb.Execute(), err=%d" ), err ) );
        CleanupStack::PopAndDestroy( buf );
	    User::Leave( err );
        }
    CleanupStack::PopAndDestroy( buf );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateClientAsuIdListTableL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::CreateClientAsuIdListTableL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::CreateCaAsuIdListTableL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreateCaAsuIdListTableL()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateCaAsuIdListTableL() IN\n" ) ) );
    
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();

    // Table columns:
    ////// NAME //////////// TYPE ///////////// Constant ///////////////////
    //| CS_CA_ASU_ID_reference  | UNSIGNED INTEGER)| KCsCaAsuIdReference |//	
    //| CS_CA_ASU_ID_data       | LONG VARBINARY   | KCsCaAsuIdData      |//		
    ////////////////////////////////////////////////////////////////////////
    _LIT( KSqlCreateTable, "CREATE TABLE %S (\
    	%S UNSIGNED INTEGER, \
    	%S LONG VARBINARY)" );

    sqlStatement.Format(
    	KSqlCreateTable, &KCsCaAsuIdListTableName, 
    	&KCsCaAsuIdReference,&KCsCaAsuIdData );

	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::CreateCaAsuIdListTableL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );	

    TInt err = iCsDb.Execute( sqlStatement );
    if ( err != KErrNone && err != KErrAlreadyExists )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::CreateCaAsuIdListTableL() \
        	iCsDb.Execute(), err=%d" ), err ) );
        CleanupStack::PopAndDestroy( buf );
	    User::Leave( err );
        }
    CleanupStack::PopAndDestroy( buf );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateCaAsuIdListTableL() OUT\n" ) ) );

    } // CCertificateStoreDatabase::CreateCaAsuIdListTableL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::CreateClientCertificateTableL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreateClientCertificateTableL()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateClientCertificateTableL() IN\n" ) ) );    
    
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();

    // Table columns:
    ////// NAME //////////// TYPE ///////////// Constant ////////////////////////////////////
    //| CS_client_cert_ASU_ID_reference   | UNSIGNED INTEGER| KCsClientCertAsuIdReference |//	
    //| CS_client_cert_data               | LONG VARBINARY  | KCsClientCertData           |//		
    /////////////////////////////////////////////////////////////////////////////////////////
    _LIT( KSqlCreateTable, "CREATE TABLE %S (\
    	%S UNSIGNED INTEGER, \
    	%S LONG VARBINARY)" );

    sqlStatement.Format(
    	KSqlCreateTable, &KCsClientCertificateTable, 
    	&KCsClientCertAsuIdReference, &KCsClientCertData );
    
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::CreateClientCertificateTableL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );	

    TInt err = iCsDb.Execute( sqlStatement );
    if ( err != KErrNone && err != KErrAlreadyExists )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::CreateClientCertificateTableL() \
        	iCsDb.Execute(), err=%d" ), err ) );
        CleanupStack::PopAndDestroy( buf );
	    User::Leave(err);
        }
    CleanupStack::PopAndDestroy( buf );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateClientCertificateTableL() OUT\n" ) ) );

    } // CCertificateStoreDatabase::CreateClientCertificateTableL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::CreateCaCertificateTableL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreateCaCertificateTableL()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateCaCertificateTableL() IN\n" ) ) );    
    
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();

    // Table columns:
    ////// NAME //////////// TYPE ///////////// Constant ////////////////////////////
    //| CS_client_cert_ASU_ID_reference   | UNSIGNED INTEGER| KCsClientCertAsuIdReference |//   
    //| CS_CA_cert_data               | LONG VARBINARY  | KCsCaCertData           |//		
    /////////////////////////////////////////////////////////////////////////////////
    _LIT( KSqlCreateTable, "CREATE TABLE %S (\
        %S UNSIGNED INTEGER, \
    	%S LONG VARBINARY)" );

    sqlStatement.Format(
    	KSqlCreateTable, &KCsCaCertificateTable, 
        &KCsCaCertAsuIdReference, &KCsCaCertData );
    
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::CreateCaCertificateTableL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );	

    TInt err = iCsDb.Execute( sqlStatement );
    if ( err != KErrNone && err != KErrAlreadyExists )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::CreateCaCertificateTableL() \
        	iCsDb.Execute(), err=%d" ), err ) );
        CleanupStack::PopAndDestroy( buf );
	    User::Leave( err );
        }
    CleanupStack::PopAndDestroy( buf );
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateCaCertificateTableL() OUT\n" ) ) );

    } // CCertificateStoreDatabase::CreateCaCertificateTableL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::CreatePrivateKeyTableL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreatePrivateKeyTableL()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreatePrivateKeyTableL() IN\n" ) ) );
    
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();

    // Table columns:
    ////// NAME ///////////////////////// TYPE ///////////// Constant /////////////////////
    //| CS_private_key_ASU_ID_reference | UNSIGNED INTEGER| KCsPrivateKeyAsuIdReference |//	
    //| CS_private_key_data             | LONG VARBINARY  | KCsPrivateKeyData           |//		
    ///////////////////////////////////////////////////////////////////////////////////////
    _LIT( KSqlCreateTable, "CREATE TABLE %S (\
    	%S UNSIGNED INTEGER, \
    	%S LONG VARBINARY)" );

    sqlStatement.Format(
    	KSqlCreateTable, &KCsPrivateKeyTable, 
    	&KCsPrivateKeyAsuIdReference, &KCsPrivateKeyData );
    
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::CreatePrivateKeyTableL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );	

    TInt err = iCsDb.Execute( sqlStatement );
    if ( err != KErrNone && err != KErrAlreadyExists )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::CreatePrivateKeyTableL() \
        	iCsDb.Execute(), err=%d" ), err ) );
        CleanupStack::PopAndDestroy( buf );
	    User::Leave( err );
        }
    CleanupStack::PopAndDestroy( buf );
        
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreatePrivateKeyTableL() OUT\n" ) ) );
    }
// ---------------------------------------------------------
// CCertificateStoreDatabase::CreateWapiCertLabeltableL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreateWapiCertLabeltableL()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateWapiCertLabeltableL() IN\n" ) ) );
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();

    // Table columns:
    ////// NAME ///////////////////////// TYPE ///////////// Constant //////////////////
    //| wapi_cs_cert_ASU_ID_reference | UNSIGNED INTEGER  |KCsCertLabelAsuIdReference|//	
    //| CS_CA_cert_label              | LONG VARBINARY    | KCsCACertLabel           |//		
    //| CS_user_cert_label            | LONG VARBINARY 	  | KCsUserCertLabel         |//
    ////////////////////////////////////////////////////////////////////////////////////

    _LIT( KSqlCreateTable, "CREATE TABLE %S (\
        %S UNSIGNED INTEGER, \
    	%S LONG VARBINARY,	\
		%S LONG VARBINARY)");

    sqlStatement.Format( KSqlCreateTable, &KCsWapiCertLabelTable, 
                        &KCsCertLabelAsuIdReference, 
    					&KCsCACertLabel,
    					&KCsUserCertLabel );
	 
    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
        "CCertificateStoreDatabase::CreateWapiCertLabeltableL() sqlStatement",
        sqlStatement.Ptr(), 
        sqlStatement.Size() ) );    
 
    TInt err = iCsDb.Execute( sqlStatement );
    if ( err != KErrNone && err != KErrAlreadyExists )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::CreateWapiCertLabeltableL() \
        	iCsDb.Execute(), err=%d" ), err ) );
            CleanupStack::PopAndDestroy( buf );
	    	User::Leave( err );
        }
    CleanupStack::PopAndDestroy( buf );
        
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateWapiCertLabeltableL() OUT\n" ) ) );

    } // CCertificateStoreDatabase::CreateWapiCertLabeltableL()



// ---------------------------------------------------------
// CCertificateStoreDatabase::CreateWapiCertFiletableL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::CreateWapiCertFiletableL()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateWapiCertFiletableL() IN\n" ) ) );
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();

    // Table columns:
    ////// NAME ///////////////////////// TYPE ///////////// Constant /////////////////
    //| CS_filename                   | VARBINARY    | KCsFileName                  |//    
    ///////////////////////////////////////////////////////////////////////////////////

    _LIT( KSqlCreateTable, "CREATE TABLE %S (%S VARBINARY)");

    sqlStatement.Format( KSqlCreateTable, &KCsWapiCertFileTable, 
                        &KCsFileName );
     
    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
        "CCertificateStoreDatabase::CreateWapiCertFiletableL() sqlStatement",
        sqlStatement.Ptr(), 
        sqlStatement.Size() ) );    

    TInt err = iCsDb.Execute( sqlStatement );
    if ( err != KErrNone && err != KErrAlreadyExists )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: CCertificateStoreDatabase::CreateWapiCertFiletableL() \
            iCsDb.Execute(), err=%d" ), err ) );
            CleanupStack::PopAndDestroy( buf );
            User::Leave( err );
        }
    CleanupStack::PopAndDestroy( buf );
        
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::CreateWapiCertFiletableL() OUT\n" ) ) );

    } // CCertificateStoreDatabase::CreateWapiCertFiletableL()

// ================= private:  Operations with view =======================


// ---------------------------------------------------------
// CCertificateStoreDatabase::GetLongBinaryDataL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::GetLongBinaryDataL(
	RDbView& aView,	HBufC8** aOutColumnValue )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetLongBinaryDataL() IN\n" ) ) );

	// Get the value from DB.
	*aOutColumnValue = HBufC8::NewLC(
		aView.ColLength( KDefaultColumnNumberOne ) ); // Buffer for the data.
	TPtr8 outColumnValuePtr8 = ( *aOutColumnValue )->Des();
	
    RDbColReadStream readStream;
	readStream.OpenLC( aView, KDefaultColumnNumberOne );
	readStream.ReadL( outColumnValuePtr8, aView.ColLength( KDefaultColumnNumberOne ) );
	readStream.Close();
	CleanupStack::Pop( &readStream );
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"CCertificateStoreDatabase::GetLongBinaryDataL() LONG BINARY value from DB",
		outColumnValuePtr8.Ptr(), outColumnValuePtr8.Size() ) );
		
	CleanupStack::Pop( *aOutColumnValue );
 
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetLongBinaryDataL() OUT\n" ) ) );
    
	} // CCertificateStoreDatabase::GetLongBinaryDataL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::GetBinaryDataL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::GetBinaryDataL(
	RDbView& aView,	HBufC8** aOutColumnValue )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetBinaryDataL() IN\n" ) ) );

	TPtrC8 dbValuePtrC8 = aView.ColDes8( KDefaultColumnNumberOne );

	*aOutColumnValue = HBufC8::NewLC( dbValuePtrC8.Size() ); // Buffer for the data.
	TPtr8 outColumnValuePtr8 = ( *aOutColumnValue )->Des();
		
	outColumnValuePtr8.Copy( dbValuePtrC8 );

	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"CCertificateStoreDatabase::GetBinaryDataL() BINARY value from DB",
		outColumnValuePtr8.Ptr(), outColumnValuePtr8.Size() ) );
		
	CleanupStack::Pop( *aOutColumnValue );
				
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetBinaryDataL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::GetBinaryDataL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::GetTableDataL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::GetTableDataL( RDbView& aView, RArray<SWapiCertEntry>& aArray )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetTableDataL() IN\n" ) ) );

	HBufC8* aOutColumnValue = NULL;
	
	if ( aView.FirstL())
	        {
	        do
	            {
	        
	            SWapiCertEntry aEntry;
	        
                aView.GetL();        
                EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                    "CCertificateStoreDatabase::GetTableDataL() aView.GetL() OK.\n" ) ) );
            
                for (TInt aColNumber = 1; aColNumber<3 ; aColNumber++ )
                    {
                    switch ( aView.ColType( aColNumber ) )
                        {
                        case EDbColText:                
                            {
                            // Buffer for unicode parameter
                            HBufC* unicodebuf = HBufC::NewLC(aView.ColLength( aColNumber ));
                            TPtr unicodeString = unicodebuf->Des();
                            unicodeString = aView.ColDes(aColNumber);
                            // Convert to 8-bit
                            if (unicodeString.Size() > 0)
                                {
                                aOutColumnValue = HBufC8::NewLC(
                                    aView.ColLength( aColNumber ) ); // Buffer for the data.
                                TPtr8 outColumnValuePtr8 = ( aOutColumnValue )->Des();
                                outColumnValuePtr8.Copy(unicodeString);
                                 if (outColumnValuePtr8.Size() == 0)
                                {
                                    User::Leave(KErrNoMemory);
                                }
                                 CleanupStack::Pop( aOutColumnValue );
                
                            } 
                            else 
                                {
                                    // Empty field. Do nothing...data remains invalid
                                }
                            CleanupStack::PopAndDestroy(unicodebuf);
                            if(aColNumber == 1)
                                aEntry.iReference = aOutColumnValue;
                            else
                                aEntry.iData = aOutColumnValue;
               
                            break;
                            }
                         case EDbColUint32:
                                {
                                    TUint value;
                                    value = eap_htonl(aView.ColUint32(aColNumber));
                                    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                                        "CCertificateStoreDatabase::GetTableDataL() \
                                        uint32 value=%d" ), value ) );

                                    aOutColumnValue = HBufC8::NewLC(
                                        aView.ColLength( aColNumber ) ); // Buffer for the data.
                                    TPtr8 outColumnValuePtr8 = ( aOutColumnValue )->Des();
                                    outColumnValuePtr8.Copy((const unsigned char *)&value, sizeof(TUint));
                                    if (outColumnValuePtr8.Size() == 0)
                                    {
                                        User::Leave(KErrNoMemory);
                                    }
                                    CleanupStack::Pop( aOutColumnValue );
                                    if (outColumnValuePtr8.Size() == 0)
                                    {
                                        User::Leave(KErrNoMemory);
                                    }
                                    if(aColNumber == 1)
                                        aEntry.iReference = aOutColumnValue;
                                    else
                                        aEntry.iData = aOutColumnValue;
                               }
                                
                                break;
                
                        case EDbColBinary:
                            {
                            EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                                "CCertificateStoreDatabase::GetTableDataL() \
                                Binary column.\n" ) ) );            
                            GetBinaryDataL( aView, &aOutColumnValue );
                            break;
                            }
                        case EDbColLongBinary:              
                            {
                            EAP_TRACE_DEBUG_SYMBIAN(
                                (_L("CCertificateStoreDatabase::GetTableDataL - Long Binary column\n")));
                        
                            RDbColReadStream readStream;
                        
                            // Get the value from DB.
                            HBufC8* valueBuf = HBufC8::NewLC(aView.ColLength(aColNumber)); // Buffer for the data.
                            TPtr8 value8 = valueBuf->Des();
                            
                            readStream.OpenLC(aView, aColNumber);
                            readStream.ReadL(value8, aView.ColLength(aColNumber));
                            readStream.Close();
                            CleanupStack::Pop(&readStream);
                            
                            EAP_TRACE_DATA_DEBUG_SYMBIAN(
                                ("CCertificateStoreDatabase::GetTableDataL: LONG BINARY value from DB",
                                value8.Ptr(), 
                                value8.Size()));
                            
                            HBufC8 *aDbBinaryColumnValue = HBufC8::NewLC(value8.Size());
                            TPtr8 aDbBinaryColumnValuePtr = (aDbBinaryColumnValue)->Des();         
        
                            aDbBinaryColumnValuePtr.Copy(value8);
                            EAP_TRACE_DATA_DEBUG_SYMBIAN(
                                ("CCertificateStoreDatabase::GetTableDataL: LONG BINARY value to caller",
                                    aDbBinaryColumnValuePtr.Ptr(), 
                                    aDbBinaryColumnValuePtr.Size()));
                            
                            CleanupStack::Pop(aDbBinaryColumnValue);
                            CleanupStack::PopAndDestroy(valueBuf);
                            
                            if(aColNumber == 1)
                                aEntry.iReference = aDbBinaryColumnValue;
                            else
                                aEntry.iData = aDbBinaryColumnValue;
                           break;
                            }       
                        default:
                            {
                            EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                                "ERROR: CCertificateStoreDatabase::GetTableDataL() \
                                Unsupported DB field:%d\n" ),
                                aView.ColType( aColNumber ) ) );    
                            User::Leave( KErrNotSupported );
                            break;
                            }
                        } // switch ( aView.ColType( KDefaultColumnNumberOne ) )
               
                    } // for
                aArray.Append(aEntry);
	            }while (aView.NextL() != EFalse);
	        } // if ( aView.FirstL() )
			
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetTableDataL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::GetBinaryDataL()

		

// ---------------------------------------------------------
// CCertificateStoreDatabase::InsertDataAndReferenceL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::InsertDataAndReferenceL(
	RDbView& aView,
	const TDesC& aReferenceColumnName,
	const TDesC& aDataColumnName,
	const TDesC16& aDataReference16,
	const TDesC8& aColumnValue )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InsertCsDataByReferenceL IN1\n" ) ) );
	
    // Convert the received reference id into integer.. 
    TUint intRef = eap_read_u32_t_network_order(
            aDataReference16.Ptr(),
            aDataReference16.Size());
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ( "CCertificateStoreDatabase::InsertCsDataByReferenceL1() \
            New entry: reference set to DB(TEXT)=%d\n" ), intRef ) );
    
   InsertDataAndReferenceL ( aView, aReferenceColumnName, aDataColumnName, intRef, aColumnValue );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InsertDataAndReferenceL OUT1\n" ) ) );

	} // CCertificateStoreDatabase::InsertDataAndReferenceL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::InsertDataAndReferenceL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::InsertDataAndReferenceL(
    RDbView& aView,
    const TDesC& aReferenceColumnName,
    const TDesC& aDataColumnName,
    const TUint aDataRef,
    const TDesC8& aColumnValue )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InsertDataAndReferenceL IN1\n" ) ) );
     
    aView.InsertL();

    // There are two columns here to set. Value and reference.  
    // Get column set so we get the correct column numbers
    CDbColSet* colSet = aView.ColSetL();
    CleanupStack::PushL( colSet );

    TDbColNo colNoReference = colSet->ColNo( aReferenceColumnName );
    TDbColNo colNoValue = colSet->ColNo( aDataColumnName );
            
    aView.SetColL( colNoReference, aDataRef );
            
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ( "CCertificateStoreDatabase::InsertDataAndReferenceL1() \
            New entry: reference set to DB(TEXT)=%d\n" ), aDataRef ) );
    
    // Set the value.
    HBufC8* valueBuf = HBufC8::NewLC( aColumnValue.Size() );
    TPtr8 valuePtr8 = valueBuf->Des();      
    valuePtr8.Copy( aColumnValue);      
    aView.SetColL( colNoValue, valuePtr8 );
            
     EAP_TRACE_DATA_DEBUG_SYMBIAN( (
        "CCertificateStoreDatabase::InsertDataAndReferenceL1() \
        New entry:Value set to DB",
        valuePtr8.Ptr(), valuePtr8.Size() ) );
    
    CleanupStack::PopAndDestroy( valueBuf );        
    CleanupStack::PopAndDestroy( colSet );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InsertDataAndReferenceL1 OUT\n" ) ) );

    } // CCertificateStoreDatabase::InsertDataAndReferenceL()
    

// ---------------------------------------------------------
// CCertificateStoreDatabase::InsertDataAndReferenceL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::InsertDataAndReferenceL(
    RDbView& aView,
    const TDesC& aReferenceColumnName,
    const TDesC& aDataColumnName,
    const TUint aDataRef,
    const TDesC& aColumnValue )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InsertDataAndReferenceL IN\n" ) ) );
    
    aView.InsertL();

    // There are two columns here to set. Value and reference.  
    // Get column set so we get the correct column numbers
    CDbColSet* colSet = aView.ColSetL();
    CleanupStack::PushL( colSet );

    TDbColNo colNoReference = colSet->ColNo( aReferenceColumnName );
    TDbColNo colNoValue = colSet->ColNo( aDataColumnName );
            
    aView.SetColL( colNoReference, aDataRef );
            
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ( "CCertificateStoreDatabase::InsertDataAndReferenceL() \
            New entry: reference set to DB(TEXT)=%d\n" ), &aDataRef ) );
    
    // Set the value.
    aView.SetColL( colNoValue, aColumnValue );
            
    CleanupStack::PopAndDestroy( colSet );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InsertDataAndReferenceL OUT\n" ) ) );

    } // CCertificateStoreDatabase::InsertDataAndReferenceL()
    

// CCertificateStoreDatabase::InsertDataL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::InsertDataL(
	RDbView& aView,
	const TDesC& aDataColumnName,
	const TDesC8& aColumnValue )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InsertDataL() IN\n" ) ) );
	
	aView.InsertL();

	// There is only one column here to set: data value.	
	// Get column set so we get the correct column number.
	CDbColSet* colSet = aView.ColSetL();
	CleanupStack::PushL( colSet );
	TDbColNo colNoValue = colSet->ColNo( aDataColumnName );
				
	// Set the value.
	HBufC8* valueBuf = HBufC8::NewLC( aColumnValue.Size() );
	TPtr8 valuePtr8 = valueBuf->Des();		
	valuePtr8.Copy( aColumnValue);		
	aView.SetColL( colNoValue, valuePtr8 );
			
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"CCertificateStoreDatabase::InsertDataL() \
		New entry: value set to DB",
	    valuePtr8.Ptr(), valuePtr8.Size() ) );
	
	// clean
	CleanupStack::PopAndDestroy( valueBuf );		
	CleanupStack::PopAndDestroy( colSet );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::InsertDataL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::InsertDataAndReferenceL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::UpdateColOneRowOneL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::UpdateColOneRowOneL(
	RDbView& aView, const TDesC8& aColumnValue )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::UpdateColOneRowOneL() IN\n" ) ) );
	
	if ( aView.IsEmptyL() ||
		 aView.CountL() > KDefaultColumnNumberOne  ||
		 aView.ColCount() == 0 ||
		 aView.ColCount() > KDefaultColumnNumberOne  )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"ERROR: CCertificateStoreDatabase::UpdateColOneRowOneL() \
			Problem with rows or columns in DB view, row count=%d, col count=%d \n" ),
			aView.CountL(), aView.ColCount() ) );
			User::Leave( KErrNotFound );				
		}	
	if ( aView.FirstL() )
		{			
		aView.UpdateL(); // Here it is update.							
		switch ( aView.ColType( KDefaultColumnNumberOne ) )
			{
			case EDbColText:				
				{
				// This value can be set as it is. The column is default 1 here.
				aView.SetColL( KDefaultColumnNumberOne, aColumnValue );
				break;
				}
            case EDbColUint32:
                {
                TUint aIntVal = eap_read_u32_t_network_order(
                        aColumnValue.Ptr(),
                        aColumnValue.Size());
                aView.SetColL( KDefaultColumnNumberOne, aIntVal );
                }
                break;

			case EDbColBinary:
				{
				aView.SetColL( KDefaultColumnNumberOne, aColumnValue );					
				break;
				}
			case EDbColLongBinary:				
				{
			    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
					"CCertificateStoreDatabase::UpdateColOneRowOneL() \
					Long binary column.\n" ) ) );
				// A stream is needed for LONG columns in DB.
				RDbColWriteStream writeStream;					
				writeStream.OpenLC( aView, KDefaultColumnNumberOne );
				writeStream.WriteL( aColumnValue );
				writeStream.Close();
				CleanupStack::Pop( &writeStream );
				break;
				}
			default:
				{
			    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
					"ERROR: CCertificateStoreDatabase::UpdateColOneRowOneL() \
					Unsupported DB field! \n" ) ) );	
				User::Leave( KErrNotSupported );
				}
			} // switch ( aView.ColType( KDefaultColumnNumberOne ) )
		} // if ( aView.FirstL() )
	else
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"ERROR: CCertificateStoreDatabase::UpdateColOneRowOneL() \
			There are no rows in view.\n" ) ) );
		User::Leave( KErrNotFound );
		}

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::UpdateColOneRowOneL() OUT\n" ) ) );

	} // CCertificateStoreDatabase::UpdateColOneRowOneL()


// ================= private:  Other =======================


// ---------------------------------------------------------
// CCertificateStoreDatabase::ConvertFromBuf8ToBuf16LC()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::ConvertFromBuf8ToBuf16LC(
	const TDesC8& aInBuf8, HBufC16** aOutBuf16 )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::ConvertFromBuf8ToBuf16LC() IN\n" ) ) );
    
	// convert utf8->unicode,
	// aInBuf8 is UTF8 string, unicode max length is
	// then the length of UTF8 string.
	// NOTE, HBufC16 length means count of 16-bit objects.
	*aOutBuf16 = HBufC16::NewLC( aInBuf8.Size() );
	TPtr16 outBufPtr16 = ( *aOutBuf16 )->Des();

	const TPtrC8 inBufPtrC8( aInBuf8 );

	CnvUtfConverter::ConvertToUnicodeFromUtf8( outBufPtr16, inBufPtrC8 );

	// print data
	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::ConvertFromBuf8ToBuf16LC() aInBuf8" ),
        inBufPtrC8.Ptr(), inBufPtrC8.Size() ) );
	
    EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "CCertificateStoreDatabase::ConvertFromBuf8ToBuf16LC() aOutBuf16" ),
	    outBufPtr16.Ptr(), outBufPtr16.Size() ) );
	
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::ConvertFromBuf8ToBuf16LC() OUT\n" ) ) );

	} // CCertificateStoreDatabase::ConvertFromBuf8ToBuf16LC()


// ---------------------------------------------------------
// CCertificateStoreDatabase::ConvertFromBuf16ToBuf8LC()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::ConvertFromBuf16ToBuf8LC(
	const TDesC16& aInBuf16, HBufC8** aOutBuf8 )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::ConvertFromBuf16ToBuf8LC() IN\n" ) ) );

    // "In UTF-8, characters are encoded using sequences of 1 to 6 octets."
    // RFC2279 - UTF-8
    const TUint KMaxNumberOfOctetsPerUtf8Char = 6;
	// Convert unicode->utf8.
	// Note, HBufC16 length means the number of 16-bit values or
    // data items represented by the descriptor.
    // Multiply number of charachters by max number of octets for char.
	*aOutBuf8 = HBufC8::NewLC( aInBuf16.Length() * KMaxNumberOfOctetsPerUtf8Char );
	TPtr8 outBufPtr8 = ( *aOutBuf8 )->Des();

	const TPtrC16 inBufPtrC16( aInBuf16 );
	
	CnvUtfConverter::ConvertFromUnicodeToUtf8( outBufPtr8, inBufPtrC16 );
  
	// print data
	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "CCertificateStoreDatabase::ConvertFromBuf16ToBuf8LC() aInBuf16" ),
	    inBufPtrC16.Ptr(), inBufPtrC16.Size() ) );
   	
	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"CCertificateStoreDatabase::ConvertFromBuf16ToBuf8LC() aOutBuf8" ),
		outBufPtr8.Ptr(), outBufPtr8.Size() ) );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::ConvertFromBuf16ToBuf8LC() OUT\n" ) ) );	
	
	} // CCertificateStoreDatabase::ConvertFromBuf16ToBuf8LC()


// ---------------------------------------------------------
// CCertificateStoreDatabase::WriteCertificateStoreStateL()
// ---------------------------------------------------------
void CCertificateStoreDatabase::WriteCertificateStoreStateL(
	TCertificateStoreState aState )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::WriteCertificateStoreStateL() IN, \
        aState=%d.\n" ), aState ) );
	    
    // There could be a case where CS DB is destroyed.
    // We just return in that case. 
    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "CCertificateStoreDatabase::SetUserCertL() CS not created.\n" ) ) );
        OpenCertificateStoreL();
        }  

    if ( !iCsSessionOpened )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"ERROR: CCertificateStoreDatabase::WriteCertificateStoreStateL() \
			CS store not opened!\n" ) ) );		
		User::Leave( KErrSessionClosed );
		}		
				
	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();
				
	_LIT( KSqlQuery, "SELECT %S FROM %S" );
	sqlStatement.Format(
		KSqlQuery,
		&KCsInitialized,
		&KCsGeneralSettingsTableName );

	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::WriteCertificateStoreStateL() sqlStatement",
		sqlStatement.Ptr(), 
		sqlStatement.Size() ) );	

 	RDbView view;
		
	User::LeaveIfError( view.Prepare(
		iCsDb, 
	    TDbQuery( sqlStatement ), 
		TDbWindow::EUnlimited ) );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::WriteCertificateStoreStateL() \
        View prepared OK.\n" ) ) );	   
	CleanupClosePushL( view );
		
	User::LeaveIfError( view.EvaluateAll() );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"CCertificateStoreDatabase::WriteCertificateStoreStateL() \
		View evaluated OK.\n" ) ) );
		
	if ( !view.FirstL() )
		{		
		view.InsertL();
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
    		"CCertificateStoreDatabase::WriteCertificateStoreStateL() \
    		View inserted OK.\n" ) ) );
		}
	else
		{
	    view.UpdateL();
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    	"CCertificateStoreDatabase::WriteCertificateStoreStateL() \
	    	View updated OK.\n" ) ) );
		}
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL( colSet );
						
	view.SetColL( colSet->ColNo( KCsInitialized ), aState );
						
	CleanupStack::PopAndDestroy( colSet ); // Delete colSet
					
	// Now it should go to the DB.
	view.PutL();	

	CleanupStack::PopAndDestroy( &view ); // Close view.	
	CleanupStack::PopAndDestroy( buf ); // Delete buf or sqlStatement.		
		
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::WriteCertificateStoreStateL() OUT\n" ) ) );
    
	} // CCertificateStoreDatabase::WriteCertificateStoreStateL()


// ---------------------------------------------------------
// CCertificateStoreDatabase::GetDbNamesFromDataTypeL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::GetDbNamesFromDataTypeL(
	ec_cs_data_type_e aDataType, TDes& aTableName,
	TDes& aReferenceColumnName, TDes& aDataColumnName )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetDbNamesFromDataTypeL() IN\n" ) ) );

    switch ( aDataType )
        {
	    case ec_cs_data_type_ca_certificate_data:
		    {
		    aTableName = KCsCaCertificateTable;
		    aReferenceColumnName = KCsCaCertAsuIdReference;
		    aDataColumnName = KCsCaCertData;
		    break;
		    }
	    case ec_cs_data_type_client_certificate_data:
		    {
		    aTableName = KCsClientCertificateTable;
		    aReferenceColumnName = KCsClientCertAsuIdReference;
		    aDataColumnName = KCsClientCertData;
		    break;
		    }
	    case ec_cs_data_type_private_key_data:
		    {
		    aTableName = KCsPrivateKeyTable;
		    aReferenceColumnName = KCsPrivateKeyAsuIdReference;
		    aDataColumnName = KCsPrivateKeyData;
		    break;
		    }
        case ec_cs_data_type_ca_asu_id:
        case ec_cs_data_type_ca_asu_id_list:
           {
            aTableName = KCsCaAsuIdListTableName;
            aReferenceColumnName = KCsCaAsuIdReference;
            aDataColumnName = KCsCaAsuIdData;
            break;
            }
        case ec_cs_data_type_client_asu_id:
        case ec_cs_data_type_client_asu_id_list:
            {
            aTableName = KCsClientAsuIdListTableName;
            aReferenceColumnName = KCsClientAsuIdReference;
            aDataColumnName = KCsClientAsuIdData;
            break;
            }
        case ec_cs_data_type_master_key:
            {
            aTableName = KCsGeneralSettingsTableName;
            aReferenceColumnName = NULL;
            aDataColumnName = KCsMasterKey;
            break;
            }
        case ec_cs_data_type_reference_counter:
            {
            aTableName = KCsGeneralSettingsTableName;
            aReferenceColumnName = NULL;
            aDataColumnName = KCsReferenceCounter;          
            break;
            }
        case ec_cs_data_type_selected_ca_id:
            {
            aTableName = KCsWapiCertLabelTable;
            aReferenceColumnName = KCsCertLabelAsuIdReference;
            aDataColumnName = KCsCACertLabel;          
            break;
            }
       case ec_cs_data_type_selected_client_id:
           {
           aTableName = KCsWapiCertLabelTable;
           aReferenceColumnName = KCsCertLabelAsuIdReference;
           aDataColumnName = KCsUserCertLabel;          
           break;
           }
 		// ... add other types when needed
        default:
        	{
		    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	            "ERROR: wapi_am_core_symbian_c::GetDbNamesFromDataTypeL() \
	            unknown dataType=%d.\n" ), aDataType ) );
			User::Leave( KErrArgument );	    	
    	    }
        } // switch
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetDbNamesFromDataTypeL() OUT\n" ) ) );

    } // CCertificateStoreDatabase::GetDbNamesFromDataTypeL


// ---------------------------------------------------------
// CCertificateStoreDatabase::GetDbNamesFromDataTypeL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::GetDbNamesFromDataTypeL(
	ec_cs_data_type_e aDataType,
	TDes& aTableName,
	TDes& aDataColumnName )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::GetDbNamesFromDataTypeL() IN\n" ) ) );

    switch ( aDataType )
	    {
		case ec_cs_data_type_master_key:
			{
		    aTableName = KCsGeneralSettingsTableName;
		    aDataColumnName = KCsMasterKey;
			break;
			}
		case ec_cs_data_type_reference_counter:
			{
		    aTableName = KCsGeneralSettingsTableName;
		    aDataColumnName = KCsReferenceCounter;			
			break;
			}
        case ec_cs_data_type_ca_certificate_data:
            {
            aTableName = KCsCaCertificateTable;
            aDataColumnName = KCsCaCertData;
            break;
            }
        case ec_cs_data_type_client_certificate_data:
            {
            aTableName = KCsClientCertificateTable;
            aDataColumnName = KCsClientCertData;
            break;
            }
        case ec_cs_data_type_ca_asu_id:
        case ec_cs_data_type_ca_asu_id_list:
           {
            aTableName = KCsCaAsuIdListTableName;
            // only table needed
            break;
            }
        case ec_cs_data_type_client_asu_id:
        case ec_cs_data_type_client_asu_id_list:
            {
            aTableName = KCsClientAsuIdListTableName;
            // only table needed
            break;
            }
        case ec_cs_data_type_selected_ca_id:
            {
            aTableName = KCsWapiCertLabelTable;
            aDataColumnName = KCsCACertLabel;          
            break;
            }
       case ec_cs_data_type_selected_client_id:
           {
           aTableName = KCsWapiCertLabelTable;
           aDataColumnName = KCsUserCertLabel;          
           break;
            }
			// ... add other types when needed	
	    default:
	    	{
		    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	            "ERROR: wapi_am_core_symbian_c::GetDbNamesFromDataTypeL() \
	            unknown dataType=%d.\n" ), aDataType ) );
			User::Leave( KErrArgument );	    	
		    }
	    } // switch
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "CCertificateStoreDatabase::GetDbNamesFromDataTypeL() OUT\n" ) ) );		
	
	} // CCertificateStoreDatabase::GetDbNamesFromDataTypeL()



// ---------------------------------------------------------
// CCertificateStoreDatabase::SetCACertL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::SetCACertL( const TInt aId, const TBuf8<KMaxIdentityLength> aSelectedCert )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ("CCertificateStoreDatabase::SetCACertL -Start")) );

    SetCertL( aId, aSelectedCert, KCsCACertLabel );
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
                ("CCertificateStoreDatabase::SetCACertL -End")) );
    return;
	}
                                  

// ---------------------------------------------------------
// CCertificateStoreDatabase::SetUserCertL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::SetUserCertL( const TInt aId, const TBuf8<KMaxIdentityLength> aSelectedCert )
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
	        ("CCertificateStoreDatabase::SetUserCertL -Start")) );

	SetCertL( aId, aSelectedCert, KCsUserCertLabel );
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
	            ("CCertificateStoreDatabase::SetUserCertL -End")) );
    return;
    }


void CCertificateStoreDatabase::SetCertL ( const TInt aId, 
        const TBuf8<KMaxIdentityLength> aSelectedCert, 
        const TDesC& aParameterName )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ("CCertificateStoreDatabase::SetCertL -Start")) );

    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "CCertificateStoreDatabase::SetUserCertL() CS not created.\n" ) ) );
        OpenCertificateStoreL();
        }  
    
    if ( !iCsSessionOpened )
        {
        EAP_TRACE_ERROR(
            iAmTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("ERROR: CCertificateStoreDatabase::SetCertL() \
                    CS store not opened!\n")));        
        User::Leave( KErrSessionClosed );
        } 
        
    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
        "CCertificateStoreDatabase::SetCertL() aSelectedCert",
        aSelectedCert.Ptr(), 
        aSelectedCert.Size() ) );    
   
    // Two SQL statements, one for addition and one for modification
    _LIT(KSQLQuery, "SELECT %S FROM %S WHERE %S=%d");
    _LIT(KSQLInsert, "SELECT * FROM %S");
            
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();
    sqlStatement.Format( KSQLQuery, &aParameterName, &KCsWapiCertLabelTable, &KCsCertLabelAsuIdReference, aId );
        
    // Prepare the view, leave if it fails
    RDbView view;   
    User::LeaveIfError(view.Prepare( iCsDb, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EUpdatable));
    User::LeaveIfError(view.EvaluateAll()); 
    CleanupClosePushL(view);
        
    // Update the data if the record exists
    if (view.FirstL())
        {
        view.UpdateL();
        // Get column set so we get the correct column numbers
        CDbColSet* colSet = view.ColSetL();
        CleanupStack::PushL(colSet);
        view.SetColL( colSet->ColNo( aParameterName ), aSelectedCert ); 
        view.PutL(); 
        CleanupStack::PopAndDestroy( colSet );
        }
    // New row. Modify the sql statement for insertion
    else
        {
        sqlStatement.Format( KSQLInsert, &KCsWapiCertLabelTable );
        // Leave if the view preparation still fails
        User::LeaveIfError ( view.Prepare( iCsDb, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly ));
        User::LeaveIfError(view.EvaluateAll());
        // Use the data insertion function to update data and reference
        InsertDataAndReferenceL ( view, KCsCertLabelAsuIdReference, aParameterName, aId, aSelectedCert );  
        view.PutL(); 
        }
         
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ("CCertificateStoreDatabase::SetCertL - labels read")) );
    CleanupStack::PopAndDestroy( &view );
    CleanupStack::PopAndDestroy( buf );
    return;
    }
        
// ---------------------------------------------------------
// CCertificateStoreDatabase::GetConfigurationL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::GetConfigurationL( const TInt aId, TDes& aCACert, TDes& aUserCert )
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
	        ("CCertificateStoreDatabase::GetConfigurationL -Start")) );
	
	_LIT(KEmpty, "None");
	// Initialize with not found
    aCACert.Copy( KEmpty );
    aUserCert.Copy( KEmpty );

    // Check whether db exists and connection is open. 
	// Zero values are returned if not 
    if ( !iCsSessionOpened || !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "CCertificateStoreDatabase::GetConfigurationL() \
                CS not opened.\n" ) ) );
        }
    else
        {  
        HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
        TPtr sqlStatement = buf->Des();
        
	    // Read ca certificate label value
	    _LIT(KSQLQuery, "SELECT %S FROM %S WHERE %S=%d");
	    sqlStatement.Format( KSQLQuery, &KCsCACertLabel, &KCsWapiCertLabelTable, 
	                        &KCsCertLabelAsuIdReference, aId );
	    
	    RDbView view;   
	    User::LeaveIfError(view.Prepare( iCsDb, TDbQuery(sqlStatement), 
	                            TDbWindow::EUnlimited, RDbView::EReadOnly));
	    CleanupClosePushL(view);
	    User::LeaveIfError(view.EvaluateAll()); 
	  
	    // Read the CA cert label
        ReadLabelTableL( view, aCACert );
	        
	    // Read the User cert label
	    sqlStatement.Format( KSQLQuery, &KCsUserCertLabel, &KCsWapiCertLabelTable, 
	                            &KCsCertLabelAsuIdReference, aId );         
	    User::LeaveIfError(view.Prepare( iCsDb, TDbQuery(sqlStatement), 
	                                    TDbWindow::EUnlimited, RDbView::EReadOnly));
	    User::LeaveIfError(view.EvaluateAll()); 
	    
	    ReadLabelTableL( view, aUserCert );

	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
	            ("CCertificateStoreDatabase::GetConfigurationL - labels read")) );

	    // Close database
	    CleanupStack::PopAndDestroy( &view );
	    CleanupStack::PopAndDestroy( buf );
	    } 
	return;
	}


// ---------------------------------------------------------
// CCertificateStoreDatabase::ReadLabelTable()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::ReadLabelTableL( RDbView& aView, TDes& aCert )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ("CCertificateStoreDatabase::ReadLabelTableL -Start")) );
    
    HBufC8* value;
    eap_variable_data_c subjectName(iAmTools);
    eap_variable_data_c label(iAmTools); 
    wapi_asn1_der_parser_c wapiAsn1(iAmTools);
    // Check memory reservations and leave if failed
    if (wapiAsn1.get_is_valid() == false || 
        subjectName.get_is_valid() == false ||
        label.get_is_valid() == false )
        {
        EAP_TRACE_ERROR(
            iAmTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("ERROR: CCertificateStoreDatabase::ReadLabelTableL() \
                    Memory allocation failed!\n")));  
        User::Leave(KErrGeneral);
        }
    
    // check if there are rows in the view
    if (aView.FirstL())
        {
        aView.GetL();
        // Store the data     
        GetLongBinaryDataL( aView, &value );
        CleanupStack::PushL(value);
        
        // If the label exists, it will be decoded
        if ( value->Size() > 0 )
            {
            eap_status_e status = label.set_copy_of_buffer( value->Ptr(), value->Size() );
            CleanupStack::PopAndDestroy( value );
            if ( status != eap_status_ok )
                {
                User::Leave(KErrGeneral);
                }
            
            status = wapiAsn1.get_decoded_subject_name( &label, &subjectName );
            if ( status != eap_status_ok )
                {
                EAP_TRACE_ERROR(
                        iAmTools,
                        TRACE_FLAGS_DEFAULT,
                            (EAPL("ERROR: CCertificateStoreDatabase::ReadLabelTable() \
                            decoding failed!\n")));  
                User::Leave(KErrGeneral);
                }
            
            // Check the lenght of the subject name part of the label,
            if ( subjectName.get_data_length() <= KCsMaxWapiCertLabelLength )
                {
                TBuf8<KCsMaxWapiCertLabelLength> tmpLabel;
                tmpLabel.Append( subjectName.get_data(subjectName.get_data_length()),
                        subjectName.get_data_length());
                        
                // Copy the data into the returned parameter
                HBufC16* label16;
                ConvertFromBuf8ToBuf16LC( tmpLabel, &label16 );
                aCert.Copy( *label16 );
                CleanupStack::PopAndDestroy(label16);
                }
            // Label is too long, write to log
            else
                {
                EAP_TRACE_ERROR(
                        iAmTools,
                        TRACE_FLAGS_DEFAULT,
                        (EAPL("ERROR: CCertificateStoreDatabase::ReadLabelTable() \
                        label too long!!\n"))); 
                }
            }
        else
            {
            CleanupStack::PopAndDestroy(value);
            }
        }
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ("CCertificateStoreDatabase::ReadLabelTableL -End")) );
    }

// ---------------------------------------------------------
// CCertificateStoreDatabase::RemoveDataFromViewL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::RemoveDataFromTableL( const TDesC& aTableName, 
                                    const TDesC& aReferenceName, TUint aRefId  )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ("CCertificateStoreDatabase::RemoveDataFromTable -Start")) );       
        
    RDbView view;
    HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
    TPtr sqlStatement = buf->Des();
    _LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d");
    
    sqlStatement.Format( KSQLQuery, &aTableName, &aReferenceName, aRefId );
    User::LeaveIfError(view.Prepare( iCsDb, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EUpdatable));
    CleanupClosePushL(view);
    
    User::LeaveIfError(view.EvaluateAll());
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
            ("CCertificateStoreDatabase::RemoveDataFromTable - view evaluated OK\n")));
    
    if (view.FirstL())
        {
        //Delete the row if it was found
        view.DeleteL(); 
        }
    else
        {
        // the row was not found
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
                ("CCertificateStoreDatabase::RemoveDataFromTable - No data found\n")));
        }
    CleanupStack::PopAndDestroy( &view );
    CleanupStack::PopAndDestroy( buf );
    }
	
// ---------------------------------------------------------
// CCertificateStoreDatabase::DeleteAPSpecificDataL( TInt aId )
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::DeleteAPSpecificDataL( const TInt aId )
	{
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL
	        ("CCertificateStoreDatabase::DeleteAPSpecificDataL -Start")) );  
	
    // If DB is not created, there is nothing to delete
    if ( !iCsDbCreated )
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "ERROR: CCertificateStoreDatabase::DeleteAPSpecificDataL() \
                CS DB doesn't exist. Don't do anything.\n" ) ) );
        return;
        }     

    // Check whether db connection is open and data exists
	if ( !iCsSessionOpened )
	    {
        EAP_TRACE_ERROR(
            iAmTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("ERROR: CCertificateStoreDatabase::DeleteAPSpecificDataL() \
                CS not opened.\n")));
	    User::Leave( KErrSessionClosed );
	    }   
  
    // Delete the row from KCsWapiCertLabelTable 
    TRAPD ( err, RemoveDataFromTableL ( KCsWapiCertLabelTable, KCsCertLabelAsuIdReference, aId ));
    
    // Leave if there were errors in one of the deletions
    User::LeaveIfError ( err );
	}

// ================= private:  Private constructors =======================


// ---------------------------------------------------------
// CCertificateStoreDatabase::CCertificateStoreDatabase()
// ---------------------------------------------------------
//
CCertificateStoreDatabase::CCertificateStoreDatabase(
    abs_eap_am_tools_c* aAmTools )
    : iState( ECertificateStoreStatesNumber )
    , iCsDbCreated( EFalse )
    , iCsSessionOpened( EFalse )
    , iAmTools( aAmTools )
    , iPartner (NULL)
    {
    }

	
// ---------------------------------------------------------
// CCertificateStoreDatabase::ConstructL()
// ---------------------------------------------------------
//
void CCertificateStoreDatabase::ConstructL()
    {
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::ConstructL() IN\n" ) ) );		

	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CCertificateStoreDatabase::ConstructL() OUT\n" ) ) );			
    
    } // CCertificateStoreDatabase::ConstructL()

// End of file.

