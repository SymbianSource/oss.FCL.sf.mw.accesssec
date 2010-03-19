/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/include/certificate_store_db_symbian.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 38 % << Don't touch! Updated by Synergy at check-out.
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
* Template version: 4.2
*/

#ifndef CERTIFICATESTOREDBSYMBIAN_H
#define CERTIFICATESTOREDBSYMBIAN_H

// INCLUDES
#include <d32dbms.h>
#include <e32cmn.h>
#include <etelmm.h>
#include <EapType.h>
#include "eap_status.h"
#include "certificate_store_db_parameters.h"
#include "eap_expanded_type.h"
#include "ec_cs_types.h"
#include "eap_array.h"
#include "WapiCertificates.h"

// CONSTANTS
const TInt KNumBytesForLimiters = 2;

struct SWapiCertEntry
{
	HBufC8* iReference;	
	HBufC8* iData;
};

// FORWARD DECLARATIONS
class abs_eap_am_tools_c;
class eap_variable_data_c;
class wapi_am_core_symbian_c;

// CLASS DECLARATION
/**
* Class implements certificate store functionality.
*/
NONSHARABLE_CLASS ( CCertificateStoreDatabase )
    {
    
    private: // CS states
    
        /**
        * State defines the type of service called.
        */ 
        enum TCertificateStoreState
            {
            ECertificateStoreNotInitialized,     /* 0 */
            ECertificateStoreInitialized,        /* 1 */
            // ...
            ECertificateStoreStatesNumber        /* 2 */   // keep always as last element
            };

                
    public:  // Constructors and destructor

        /**
        * Two-phased constructor.
        * 
        * @param aAmTools Pointer to adaptation module tools.
        */
        static CCertificateStoreDatabase* NewL(
                abs_eap_am_tools_c* aAmTools );
	
        /**
        * Destructor.
        */
        virtual ~CCertificateStoreDatabase();

        
    public:	// New, open/close/destroy functionality	
		
        /**
        * Open certificate store database.
        * 
        * Database and tables are created.
        * Method leaves if an error occurs.
        */ 
        void OpenCertificateStoreL();
	
        /**
        * Close certificate DB and session.
        */ 
        void Close();	

        /**
        * Destroy certificate store.
        * 
        * @return General symbian error.
        */ 
	    TInt DestroyCertificateStore();
	    
        /**
        * Set core partner.
        * 
        * This method is used to deliver pointer of core class.
        */ 

	    void SetCorePartner(wapi_am_core_symbian_c *partner);
	    
    public: // New 
       
	    /**
	    * Function initializes the certificate store.
	    * 
	    * This function is completed by function call
	    * complete_initialize_certificate_store() .
	    */
        void InitializeCertificateStoreL();

	    /**
	    * Function cancels all certificate_store store operations.
	    */
	    void CancelCertificateStoreStoreOperations();

	
    public: // New, get/set/remove data in database    
        
        /**
        * Get data from CS by reference.
        * 
        * Memory is allocated inside the method.
        * The caller is responsible for memory cleaning.
        * Note that method can leave.
        * @param aDataType Type of data (CA cert., client cert., or private key).
        * @param aDataReference Reference used to search data.
        * @param aOutColumnValue Returned column value. The caller is responsible
        *                        for memory cleaning.
        */ 
        void GetCsDataByReferenceL( ec_cs_data_type_e aDataType,
           	                        const TDesC8& aDataReference,
       	                            HBufC8** aOutColumnValue );
        
        /**
        * Get data from CS by int reference.
        * 
        * Memory is allocated inside the method.
        * The caller is responsible for memory cleaning.
        * Note that method can leave.
        * @param aDataType Type of data (CA cert., client cert., or private key).
        * @param aDataReference Reference used to search data.
        * @param aOutColumnValue Returned column value. The caller is responsible
        *                        for memory cleaning.
        */ 
        void GetCsDataByReferenceL( ec_cs_data_type_e aDataType,
           	                        const TUint aDataReference,
       	                            HBufC8** aOutColumnValue );
        
        /**
        * Get data from CS by reference.
        * 
        * Memory is allocated inside the method.
        * The caller is responsible for memory cleaning.
        * Note that method can leave.
        * @param aDataType Type of data to be searched in CS.
        * @param aOutColumnValue Returned column value. The caller is responsible
        *                        for memory cleaning.
        */ 
        void GetCsDataL( ec_cs_data_type_e aDataType,
          	            HBufC8** aOutColumnValue,
						RArray<SWapiCertEntry>& aArray,
						TBool aGetAll);
 
   
        /**
        * Set CS data by reference.
        * 
        * @param aDataType Type of data to be saved in CS.
        * @param aColumnValue Reference to column value descriptor.
        * @param aDataReference Reference used to search data.
        * @param aIsNewEntry ETrue - insert new item,
        *                    EFalse - update existing one.
        */ 
        void SetCsDataByReferenceL( ec_cs_data_type_e aDataType,
        		                    const TDesC8& aColumnValue,
        		                    const TDesC8& aDataReference,
        		                    const TBool aIsNewEntry );

        /**
        * Set CS data by int reference.
        * 
        * @param aDataType Type of data to be saved in CS.
        * @param aColumnValue Reference to column value descriptor.
        * @param aDataReference Reference used to search data.
        * @param aIsNewEntry ETrue - insert new item,
        *                    EFalse - update existing one.
        */ 
        void SetCsDataByReferenceL( ec_cs_data_type_e aDataType,
        		                    const TDesC8& aColumnValue,
        		                    const TUint aDataReference,
        		                    const TBool aIsNewEntry );


        /**
        * Set CS data.
        * 
        * @param aDataType Type of data to be saved in CS.
        * @param aColumnValue Reference to column value descriptor.
        * @param aIsNewEntry  ETrue - insert new item,
        *                     EFalse - update existing one.
        */ 
        void SetCsDataL( ec_cs_data_type_e aDataType,
        		         const TDesC8& aColumnValue,
        		         const TBool aIsNewEntry );
        
        
        /**
        * Remove CS data by reference.
        * 
        * Method leaves if an error occurs.
        * @param aDataType Type of data to be saved in CS.
        * @param aColumnValue Reference to column value descriptor.
        * @param aDataReference Reference used to search data.
        */ 
        void RemoveCsDataByReferenceL( ec_cs_data_type_e aDataType,
                                       const TDesC8& aColumnValue,
                                       const TDesC8& aDataReference );

        /**
        * Remove CS data by int reference.
        * 
        * Method leaves if an error occurs.
        * @param aDataType Type of data to be saved in CS.
        * @param aColumnValue Reference to column value descriptor.
        * @param aDataReference Reference used to search data.
        */ 
        void RemoveCsDataByReferenceL( ec_cs_data_type_e aDataType,
                                       const TDesC8& aColumnValue,
                                       const TUint aDataReference );

        /**
        * Remove CS data by data type.
        * 
        * @param aDataType Type of data to be saved in CS.
        * @param aColumnValue Reference to column value descriptor. 
        */ 
        void RemoveCsDataL( ec_cs_data_type_e aDataType,
        	                const TDesC8& aColumnValue );
        
        /**
        * Remove CS data by from table matching the id.
        * 
        * @param aTableName The table to be modified
        * @param aReferenceName The reference column 
        * @param aRefId The reference id 
        */ 
        void RemoveDataFromTableL( const TDesC& aTableName, const TDesC& aReferenceName, TUint aRefId  );
        
        /**
        * Remove specific rows from all the AP specific tables.
        * 
        * @param aId The reference id (service table id )
        */
        void DeleteAPSpecificDataL( const TInt aId );
        
    public: // New, boolean conditions
    
	    /**
        * Check if certificate store was initialized by common side.
        * 
        * @return ETrue - initilized, EFalse - not initialized.
        */ 
	    TBool IsInitializedL();
	    		

    public: // Access

        /**
        * Return reference to certificate store DB.
        */ 
        RDbNamedDatabase& GetCertificateStoreDb();
    
    public: // WAPI certificate label get/set functionality
    		
        /**
        *  Set WAPI CA certificate identity KCsWapiCertLabelTable table, matching the id
        */ 
        void SetCACertL( const TInt aId, const TBuf8 <KMaxIdentityLength> aSelectedCert );
        
        /**
        * Set WAPI user certificate identity to the KCsWapiCertLabelTable table, matching the id
        */ 
        void SetUserCertL( const TInt aId, const TBuf8 <KMaxIdentityLength> aSelectedCert);
        
        /**
        * Set WAPI certificate identity to the KCsWapiCertLabelTable table for the
        * given parameter, matching the id 
        */ 
        void SetCertL ( const TInt aId, const TBuf8<KMaxIdentityLength> aSelectedCert, 
                 const TDesC& aParameterName );
        
        /**
        * Get certificate labels set to the KCsWapiCertLabelTable table matching the id
        */ 
        void GetConfigurationL( const TInt aId, TDes& aCACert, TDes& aUserCert );
        
        /**
        * Reads and decodes the label data from the given view
        */ 
        void ReadLabelTableL( RDbView& aView, TDes& aCert );
        
       
        
                                          
    private: // New, database, tables
	
        /**
        * Create CS database and all necessary tables.
        * 
        * Note that method can leave.
        */
	    void CreateCertificateStoreL();
	    
	    /**
	    * Create CS database.
	    * 
	    * Note that method can leave.
	    */ 
	    void CreateDatabaseL();
	    
	    /**
	    * Create table for general settings.
	    * 
	    * Create table for general settings, such as
	    * CS password, reference counter, master key,
	    * initialization flag, CS password max. validity time,
	    * CS password last identity time, CS WAPI session max
	    * validity time, CS WAPI session last full auth. time.
	    * Note that method can leave.
	    */ 
	    void CreateGeneralSettingsTableL();	    	    
	    
	    /**
	    * Create table that stores list of client ASU IDs.
	    * 
	    * Note that method can leave.
	    */ 	    
	    void CreateClientAsuIdListTableL();
	    
	    /**
	    * Create table that stores list of CA ASU IDs.
	    * 
	    * Note that method can leave.
	    */ 
	    void CreateCaAsuIdListTableL();
	    
	    /*
	    * Create table that stores list of client certificate data.
	    * 
	    * Note that method can leave.
	    */ 
	    void CreateClientCertificateTableL();
	    
	    /**
	    * Create table that stores list of CA certificate data.
	    * 
	    * Note that method can leave.
	    */ 
	    void CreateCaCertificateTableL();
	    
	    /**
	    * Create table that stores list of private key data.
	    * 
	    * Note that method can leave.
	    */ 
	    void CreatePrivateKeyTableL();
	    
	    /**
	    * Create table that stores the WAPI certificate labels
	    */ 
	    void CreateWapiCertLabeltableL();
	    
	    /**
	     * Create table that stores the WAPI certificate files
	    */ 
        void CreateWapiCertFiletableL();

    private: // Operations with RDbView rowset  

        /**
	    * Get long binary data.
	    * 
	    * Read long binary data using stream from DB view.
	    * Note that the caller is responsible for memory cleaning.
	    * Note that method can leave.
	    * @param aView Reference to rowsets from an SQL query
	    * @param aOutColumnValue Returned column value. Memory is allocated
	    *                        inside the method.
	    */ 
	    void GetLongBinaryDataL( RDbView& aView, HBufC8** aOutColumnValue );
	
        /**
	    * Get binary data.
	    * 
	    * Read binary data from DB view.
	    * Note that the caller is responsible for memory cleaning.
	    * Note that method can leave.
	    * @param aView Reference to rowsets from an SQL query.
	    * @param aOutColumnValue Returned column value. Memory is allocated
	    *                        inside the method.
	    */ 
	    void GetBinaryDataL( RDbView& aView, HBufC8** aOutColumnValue );
	
        /**
	    * Get binary data.
	    * 
	    * Read binary data from DB view.
	    * Note that the caller is responsible for memory cleaning.
	    * Note that method can leave.
	    * @param aView Reference to rowsets from an SQL query.
	    * @param aArray Returned column values. Memory is allocated
	    *                        inside the method.
	    */ 
		void GetTableDataL( RDbView& aView, RArray<SWapiCertEntry>& aArray );
								
        /**
        * Insert data and reference to view.
        * 
        * Note that method can leave.
        * @param aView Reference to rowset from SQL query.
        * @param aReferenceColumnName Column name for reference.
        * @param aDataColumnName Column name for data.
        * @param aDataReference16 Reference to descriptor containing
        *                         data reference value in unicode.
        * @param aColumnValue Reference to descriptor containing column value.
        */ 
        void InsertDataAndReferenceL( RDbView& aView,
                                      const TDesC& aReferenceColumnName,
                                      const TDesC& aDataColumnName,
                                      const TDesC16& aDataReference16,
                                      const TDesC8& aColumnValue );
        
        /**
        * Insert data and reference to view.
        * 
        * Note that method can leave.
        * @param aView Reference to rowset from SQL query.
        * @param aReferenceColumnName Column name for reference.
        * @param aDataColumnName Column name for data.
        * @param aDataRef Reference to the row to be modified
        * @param aColumnValue Reference to descriptor containing column value.
        */
        void InsertDataAndReferenceL( RDbView& aView,
                                      const TDesC& aReferenceColumnName,
                                      const TDesC& aDataColumnName,
                                      const TUint aDataRef,
                                      const TDesC8& aColumnValue );
        
        /**
        * Insert data and reference to view.
        * 
        * Note that method can leave.
        * @param aView Reference to rowset from SQL query.
        * @param aReferenceColumnName Column name for reference.
        * @param aDataColumnName Column name for data.
        * @param aDataRef Reference to the row to be modified
        * @param aColumnValue Reference to descriptor containing column value.
        */
        void InsertDataAndReferenceL( RDbView& aView,
                                      const TDesC& aReferenceColumnName,
                                      const TDesC& aDataColumnName,
                                      const TUint aDataRef,
                                      const TDesC& aColumnValue );

        /**
        * Insert data value to view.
        * 
        * Note that method can leave.
        * @param aView Reference to rowset from SQL query.
        * @param aDataColumnName Column name for data.
        * @param aColumnValue Reference to descriptor containing column value.
        */ 
		void InsertDataL( RDbView& aView,
				          const TDesC& aDataColumnName,
				          const TDesC8& aColumnValue );		

        /**
        * Update view with specified column value.
        * 
        * There should be only one-row-one-column in view.
        * Note that method can leave.
        * @param aView Reference to rowset from SQL query.
        * @param aColumnValue Reference to descriptor containg column value.
        */ 
        void UpdateColOneRowOneL( RDbView& aView,
        		                  const TDesC8& aColumnValue );
        

    private: // Other

        /**
        * Convert from utf8 to unicode.
        * 
        * Note that the caller is responsible for memory cleaning.
        * Note that method can leave.
        * @param aInBuf Const reference to the input buffer.
        * @param aOutBuf Returned converted buffer, memory is allocated inside
        *                the method. 
        */
        void ConvertFromBuf8ToBuf16LC( const TDesC8& aInBuf8, HBufC16** aOutBuf16 );

        /**
        * Convert from unicode to utf8.
        * 
        * Note that the caller is responsible for memory cleaning.
        * Note that method can leave.
        * @param aInBuf Const reference to the input buffer.
        * @param aOutBuf Returned converted buffer, memory is allocated inside
        *                the method. 
        */
        void ConvertFromBuf16ToBuf8LC( const TDesC16& aInBuf16, HBufC8** aOutBuf8 );

	    /**
        * Writes certificate store state in CS database.
        * 
	    * If CS object is deleted, the state can be recovered
	    * from database.
	    * Note that method can leave.
	    * @param aState Parameter defines CS state.
	    */ 
        void WriteCertificateStoreStateL( TCertificateStoreState aState );	    
    
	    /**
	    * Get database names.
	    *  
	    * According to data type, return table, reference and data
	    * column names.
	    * Note that method can leave.
	    * @param aDataType Certificate store data types.
	    * @param aTableName Table name.
	    * @param aReferenceColumnName Column name of reference.
	    * @param aDataColumnName Column name of data.
	    */ 
	    void GetDbNamesFromDataTypeL( ec_cs_data_type_e aDataType,
	     		                      TDes& aTableName,
	     		                      TDes& aReferenceColumnName,
	     		                      TDes& aDataColumnName );
	     
	     /**
	     * Get database names.
	     *  
	     * According to data type, return table and data
	     * column names.
	     * Note that method can leave.
	     * @param aDataType Certificate store data types.
	     * @param aTableName Table name.
	     * @param aDataColumnName Column name of data.
	     */ 
	     void GetDbNamesFromDataTypeL( ec_cs_data_type_e aDataType,
	      		                       TDes& aTableName,
	                                   TDes& aDataColumnName );

	      
    private: // Private constructors

        /**
        * C++ default constructor.
        */
        CCertificateStoreDatabase( abs_eap_am_tools_c* aAmTools );
        
        /**
        * By default Symbian 2nd phase constructor is private.
        */
        void ConstructL();
	
        
    private: // Data
	
        /**
        * State defines the type of the requested service.
        */ 
	    TCertificateStoreState iState;	
	
        /**
        * Generic database implementation.
        */ 
	    RDbNamedDatabase iCsDb;

        /**
        * Represents a session with the DBMS server.
        */ 
	    RDbs iCsDbSession;	
	
        /**
        * ETrue - CS created, EFalse - not.
        */ 
	    TBool iCsDbCreated;
	    
        /**
        * ETrue - CS session opened, EFalse - not.
        */ 
	    TBool iCsSessionOpened;
	
        /**
        * Adaptation module tools.
        */ 
	    abs_eap_am_tools_c* iAmTools;
	    
		// pointer to core class, to provide method interface	   
        wapi_am_core_symbian_c *iPartner;
		
    }; // NONSHARABLE_CLASS ( CCertificateStoreDatabase )

#endif // CERTIFICATESTOREDBSYMBIAN_H

// End of file.
