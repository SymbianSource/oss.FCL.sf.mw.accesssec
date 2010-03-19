/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/include/wapi_am_core_symbian.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 41.2.1.1.2 % << Don't touch! Updated by Synergy at check-out.
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




#if !defined(_WAPI_AM_CORE_SYMBIAN_H_)
#define _WAPI_AM_CORE_SYMBIAN_H_

// INCLUDES
#include <d32dbms.h>
#include <e32cmn.h>
#include <etelmm.h>
#include <wdbifwlansettings.h>
#include "eapol_key_types.h"
#include "wapi_am_base_core.h"
#include "ec_am_base_certificate_store.h"
#include "wapi_types.h"
#include "eap_am_trace_symbian.h"
#include "abs_wapi_am_core.h"
#include "abs_ec_am_certificate_store.h"
#include "certificate_store_db_symbian.h"

// FORWARD DECLARATIONS
class eap_am_tools_symbian_c;
class eap_file_config_c;
class abs_ec_am_base_certificate_store_c;
class abs_wapi_am_base_core_c;
class CCertificateStoreDatabase;

const TInt KMaxWPAPSKPasswordLength = 64;
const TInt KWPAPSKLength = 32;
const TInt KCsMaxWapiCertLabelLen = 255;


// CLASS DECLARATION
class wapi_am_core_symbian_c
    :  public CActive,
    public wapi_am_base_core_c,
	public abs_eap_base_timer_c

{
private: // AO states
    /**
    * Possible states of active object, which are
    * used in asynch. requests.
    */ 
    enum TWapiState 
	    {
	    EWapiHandlingDeviceSeedQueryState,  /* 0 */
#if defined( WAPI_USE_UI_NOTIFIER )   		    
	    EWapiQueryCertFilePasswordState,
	    EWapiQueryImportFilePasswordState,
#endif   		    
	    EWapiStatesNumber                   /*  */ // keep always as last element
	    };

public:

    virtual ~wapi_am_core_symbian_c();	
	
	///////////////////////////////////////////////////////////////
	/* These are called from WLM via CEapol */

	static wapi_am_core_symbian_c * NewL(
		abs_eap_am_tools_c *const,
		abs_wapi_am_core_c* const aPartner,
		const bool aIsClient);
	
	
   static wapi_am_core_symbian_c * NewL(
		abs_eap_am_tools_c *const,
        abs_wapi_am_core_c* const aPartner,
        CCertificateStoreDatabase* aCertificateStoreDb,
        const bool aIsClient);

   /**
   * The shutdown() function is called before the destructor of the 
   * object is executed. During the function call the object 
   * could shutdown the operations, for example cancel timers.
   * Each derived class must define this function.
   */
   EAP_FUNC_EXPORT eap_status_e shutdown();

   /** Function sets partner object of adaptation module of certificate store.
	 *  Partner object is the certificate store object.
	 */
	void set_am_certificate_store_partner(abs_ec_am_certificate_store_c * const partner);

	eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	eap_status_e cancel_all_timers();

	eap_status_e timer_expired(const u32_t id, void *data);

	eap_status_e timer_delete_data(const u32_t id, void *data);
	
  /**
	* Import is completed and list of available certs can be read
	*/ 
	eap_status_e complete_start_certificate_import();
	    
	/**
	* Interface function for calling the function to store the lists of available certificates
	*/ 
	eap_status_e complete_query_certificate_list(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const ca_certificates,
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const user_certificates);
	
	/**
	 * Store received lists of available certificates
	 */ 
	eap_status_e complete_query_certificate_listL(
	    EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const ca_certificates,
	    EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const user_certificates);
  
	/**
	 * This is called by WapiCertificates module used by the UI.
	 * It gets the available certificate labels
	 */ 
  void GetAllCertificateLabelsL( RArray<TBuf<KCsMaxWapiCertLabelLen> > **aUserCerts,
                                      RArray<TBuf<KCsMaxWapiCertLabelLen> > **aCACerts,
                                      RArray<TBuf8<KMaxIdentityLength> > **aUserCertsData,
                                      RArray<TBuf8<KMaxIdentityLength> > **aCACertsData,
                                      TRequestStatus& aStatus);

  /** Client calls this function.
    *  WAPI AM erases imported certificates list & other vital things.
    */
    EAP_FUNC_IMPORT eap_status_e reset();

protected:
	
	wapi_am_core_symbian_c(
			abs_eap_am_tools_c *const,
			abs_wapi_am_core_c * const aPartner,
		const bool is_client_when_true);
	
	   wapi_am_core_symbian_c(
			abs_eap_am_tools_c *const,
			abs_wapi_am_core_c * const aPartner,
	        CCertificateStoreDatabase* aCertificateStoreDb,
	        const bool is_client_when_true);
	   
	
	void ConstructL();

	
    protected: // from CActive
    
        /**
        * RunL from CActive
        */    
	    void RunL();

	    /**
        * DoCancel from CActive
        */    
	    void DoCancel();


    protected: // from wapi_am_base_core_c
    

	    /***************************************/
	    /* from wapi_am_base_core_c */
	    /***************************************/
	
	    EAP_FUNC_IMPORT abs_wapi_am_core_c * get_am_partner();
	
        /** Function sets partner object of adaptation module of WAPI.
	    *  Partner object is the WAPI core object.
	    */
	    EAP_FUNC_IMPORT void set_am_partner(abs_wapi_am_core_c * const partner);

	    EAP_FUNC_IMPORT eap_status_e configure();

	    EAP_FUNC_IMPORT bool get_is_valid();

	    /** Client calls this function.
	    *  WAPI AM could make some fast operations here, heavy operations should be done in the reset() function.
	    */
	    EAP_FUNC_IMPORT eap_status_e authentication_finished(
		    const bool true_when_successfull);

	    /**
	    * The type_configure_read() function reads the configuration data identified
	    * by the field string of field_length bytes length. Adaptation module must direct
	    * the query to some persistent store.
	    * @param field is generic configure string idenfying the required configure data.
	    * @param field_length is length of the field string.
	    * @param data is pointer to existing eap_variable_data object.
	    */
	    EAP_FUNC_IMPORT eap_status_e type_configure_read(
		    const eap_configuration_field_c * const field,
		    eap_variable_data_c * const data);

        /**
	    * The type_configure_write() function writes the configuration data identified
	    * by the field string of field_length bytes length. Adaptation module must direct
	    * the action to some persistent store.
	    * @param field is generic configure string idenfying the required configure data.
	    * @param field_length is length of the field string.
	    * @param data is pointer to existing eap_variable_data object.
	    */
	    EAP_FUNC_IMPORT eap_status_e type_configure_write(
		    const eap_configuration_field_c * const field,
		    eap_variable_data_c * const data);

	    
    protected: // from ec_am_base_certificate_store_c

    
	    /***************************************/
	    /* from ec_am_base_certificate_store_c */
	    /***************************************/
	
	    /**
        * Function initializes the certificate store.
	    * This function is completed by complete_initialize_certificate_store() function call.
	    */
	    EAP_FUNC_IMPORT eap_status_e initialize_certificate_store(
		    const wapi_completion_operation_e completion_operation);

	    /**
	    * Function reads the certificate store data referenced by parameter in_references.
	    * This function is completed by complete_read_certificate_store_data() function call.
	    */
	    EAP_FUNC_IMPORT eap_status_e read_certificate_store_data(
		    const ec_cs_pending_operation_e in_pending_operation,
		    EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references);

	    /**
	    * Function writes the certificate store data referenced by parameter in_references_and_data_blocks.
	    * This function is completed by complete_write_certificate_store_data() function call.
	    */
	    EAP_FUNC_IMPORT eap_status_e write_certificate_store_data(
		    const bool when_true_must_be_synchronous_operation,
		    const ec_cs_pending_operation_e in_pending_operation,
		    EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references_and_data_blocks);

	    /**
	    * Function completes the add_imported_certificate_file() function call.
	    */
	    EAP_FUNC_IMPORT eap_status_e complete_add_imported_certificate_file(
		    const eap_status_e in_completion_status,
		    const eap_variable_data_c * const in_imported_certificate_filename);

	    /**
	    * Function completes the remove_certificate_store() function call.
	    */
	    EAP_FUNC_IMPORT eap_status_e complete_remove_certificate_store(
		    const eap_status_e in_completion_status);

	    /**
	    * Function cancels all certificate_store store operations.
	    */
	    EAP_FUNC_IMPORT eap_status_e cancel_certificate_store_store_operations();

	    /**
	    * The set_session_timeout() function changes the session timeout timer to be elapsed after session_timeout_ms milliseconds.
	    */
	    EAP_FUNC_IMPORT eap_status_e set_session_timeout(
		    const u32_t session_timeout_ms);

	    /**
	    * This is notification of internal state transition.
	    * This is used for notifications, debugging and protocol testing.
	    * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	    * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully. EAP-type MUST send these
	    * two notifications to lower layer.
	    * These two notifications are sent using EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	    * See also eap_state_notification_c.
	    */
	    EAP_FUNC_IMPORT void state_notification(
		    const abs_eap_state_notification_c * const state);

	    /**
	    * The read_configure() function reads the configuration data identified
	    * by the field string of field_length bytes length. Adaptation module must direct
	    * the query to some persistent store.
	    * @param field is generic configure string idenfying the required configure data.
	    * @param field_length is length of the field string.
	    * @param data is pointer to existing eap_variable_data object.
	    * 
	    * EAP-type should store it's parameters to an own database. The own database should be accessed
	    * through adaptation module of EAP-type. See eap_am_type_tls_peap_simulator_c::type_configure_read.
	    */
	    EAP_FUNC_IMPORT eap_status_e read_configure(
		    const eap_configuration_field_c * const field,
		    eap_variable_data_c * const data);
	
	    
    private: // New, timer expired process methods
    
        /**
        * Process initialize-certificate-store request.
        * 
        * @return EAP status.
        */ 
        eap_status_e ProcessInitCertificateStore();

        /**
        * Process add-certificate-file request.
        * 
        * @return EAP status.
        */ 
        eap_status_e ProcessAddCertificateFile();

        /**
        * Process read-certificate-store-data request.
        * 
        * @return EAP status.
        */ 
        eap_status_e ProcessReadCertificateStoreData();
        
        /**
        * Process write-certificate-store-data request.
        * 
        * @return EAP status.
        */ 
        eap_status_e ProcessWriteCertificateStoreData();
     	

    private: // New, writing to CS

        /**
        * Write data to certificate store.
        * Method leaves if an error occurs.
        */ 
        void WriteCertificateStoreDataL();
        
        /**
        * Write certificate store data with reference.
        * 
        * Method re-delivers writing request to certificate store.
        * Method leaves if an error occurs.
        * 
        * @param aDataReference Certificate store data item.
        * @param aIsNewEntry ETrue - new entry, EFalse - otherwise.
        */ 
	    void WriteCsDataWithReferenceL(
	    	const ec_cs_data_c* const aDataReference,
            TBool aIsNewEntry );				    

	    /**
	    * Write certificate store data.
        *
        * Method re-delivers writing request to certificate store.
        * Method leaves if an error occurs.
        * 
        * @param aData Certificate store data item.
        * @param aIsNewEntry ETrue - new entry, EFalse - otherwise.
	    */ 
        void WriteCsDataL(
        	const ec_cs_data_c* const aData,
        	TBool aIsNewEntry );
        
        /**
        * Delete certificate store data item found by reference.
        * 
        * Method leaves if an error occurs.
        * 
        * @param aDataReference Data reference used to search data in the table.
        */ 
        void DeleteCsDataWithReferenceL(
        	const ec_cs_data_c* const aDataReference );
        

    private: // New, reading from CS
    
        /**
        * Read data from certificate store.
        * Method leaves if an error occurs.
        */ 
        void ReadCertificateStoreDataL();
        
        /**
        * Read data using reference from certificate store.
        * 
        * Method takes care about elegant cleaning of memory 
        * allocated by CS and adding new data item to EAP array.
        * Method leaves if an error occurs.
        * 
        * @param aDataReference Data reference used to search data in the table.
        */ 
        void ReadCsDataByReferenceL(
        	const ec_cs_data_c* const aDataReference );
          
        /**
        * Read specified data type from certificate store.
        * 
        * Method takes care about elegant cleaning of memory 
        * allocated by CS and adding new data item to EAP array.
        * Method leaves if an error occurs.
        * 
        * @param aDataReference Data reference used to search data in the table.
        */ 
        void ReadCsDataL( const ec_cs_data_c* const aDataReference );

        /**
        * Get certificate store data by reference.
        * 
        * Method re-delivers reading request to certificate store.
        * Memory for returned buffer is allocated by CS.
        * Memory ownership is transfered to the caller.
        * Note that the method can leave.
        * 
        * @param aDataReference Reference used to search data.
        * @param aOutColumnValue Returned data buffer.
        */ 
        void GetCsDataByReferenceL(
        	const ec_cs_data_c* const aDataReference,
        	HBufC8** aOutColumnValue ); 
        
        /**
        * Get certificate store data by data type.
        *
        * Method re-delivers reading request to certificate store.
        * Memory for returned buffer is allocated by CS.
        * Memory ownership is transfered to the caller.
        * Method leaves if an error occurs.
        * 
        * @param aDataType Type of data used to search data in table.
        * @param aOutColumnValue Returned data buffer.
        */ 
        void GetCsDataL( ec_cs_data_type_e aDataType,
          	             HBufC8** aOutColumnValue );

        /**
        * Get certificate store table by data type.
        *
        * Method re-delivers reading request to certificate store.
        * Memory for returned buffer is allocated by CS.
        * Memory ownership is transfered to the caller.
        * Method leaves if an error occurs.
        * 
        * @param aDataType Type of data used to search data in table.
        * @param aArray Returned data buffer.
        */ 
  		void GetCsTableL(ec_cs_data_type_e aDataType,
  			HBufC8** aOutColumnValue,
  			RArray<SWapiCertEntry>& aArray);

        /**
        * Read password.
        * 
        * Read password from certificate store.
        * Method leaves if an error occurs.
        * @param aDataReference Password reference.
        */ 
        void ReadPasswordL( const ec_cs_data_c* const aDataReference );

        /**
        * Read device seed.
        * 
        * Read device seed from certificate store.
        * Method leaves if an error occurs.
        * 
        * @param aDataReference Device seed reference.
        */ 
        void ReadDeviceSeedL( const ec_cs_data_c* const aDataReference );
        				
        /**
        * Read certificate file password.
        * 
        * Read certificate file password from certificate store.
        * Method leaves if an error occurs.
        * 
        * @param aDataReference Reference of certificate file password.
        */ 
		void ReadCertificateFilePasswordL(
			const ec_cs_data_c* const aDataReference );		

        /**
         * Add new CS data object to the list.
         *
         * Method leaves if an error occurs.
         * @param aDataReference Certificate store data reference.
         * @param aData Certificate store data.
         */ 
         void AddObjectL( const ec_cs_data_c* const aDataReference,
         		          const eap_variable_data_c* const aData );
         

         
   private: // New, start/complete asynch. requests
    
        /*
        * Start asynchronous request.
        * 
        * @param aState State of active object that defines the type
        *               of request to be served.
        * @return ETrue - if request started succefully, EFalse - otherwise.
        */ 
        TBool StartAsynchRequest( TWapiState aState );

#if defined( WAPI_USE_UI_NOTIFIER )   		    
        
        /**
        * Ask from user certificate files password.
        */ 
        StartQueryCertFilePassword();

        /**
        * Complete start-query-cert-file-password request.
        */ 
        CompleteQueryCertFilePassword();

        /**
        * Ask from user import file password.
        */ 
        StartQueryImportFilePassword();
        
        /**
        * Complete start-query-import-file-password request.
        */ 
        CompleteQueryImportFilePassword();
        
#endif // WAPI_USE_UI_NOTIFIER 
        
    private: // New, complete asynch. query methods in active object    
    
        void CompleteHandlingDeviceSeedQueryState();	    

        
    private: // New methods, misc
    
        void CopyBufToEapVarL( const TDesC8& aInBuf,
            eap_variable_data_c& aOutEapVar );

   
    	void set_is_valid();
    	
    	eap_status_e CreateDeviceSeedAsync();

    	void CompleteCreateDeviceSeed( TInt aStatus );

    	TInt CreateMMETelConnectionL();

    	void DisconnectMMETEL();	

    	eap_status_e ImportFilesL();
    	
    	void UpdatePasswordTimeL();
    	
    	void CheckPasswordTimeValidityL();
    	
    	TInt64 ReadIntDbValueL(
    			RDbNamedDatabase& aDb,
    			const TDesC& aColumnName,
    			const TDesC& aSqlStatement );
    	
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
        * Check if filename is in db.
        * 
        * Method leaves if an error occurs.
        * @param aFileName contains filename to be checked.
        * Return value ETrue indicates found, and EFalse indicates not found
        */ 
        TBool CheckFilenameL(TPtr8 aFileNamePtr );
        
        /**
        * This is internal functionality of complete_add_imported_certificate_file.
        * 
        * Method can be used also, if complete_add_imported_certificate_file is not called.
        * Method leaves if an error occurs.
        */ 
        void CompleteAddImportedCertificateFileL(const eap_variable_data_c * const in_imported_certificate_filename);

    private: // Data

    
        /**
        * Timer IDs which are usually used in asynch. calls
        * from common side.
        */ 
        enum TWapiAmCoreTimerId
            {
            EWapiInitCertificateStoreTimerId,       /* 0 */
            EWapiAddCertificateFileTimerId,         /* 1 */
            EWapiReadCertificateStoreDataTimerId,   /* 2 */
            EWapiWriteCertificateStoreDataTimerId,  /* 3 */
            // ...
            EWapiTimerIdsNumber                     /* 4 */ // keep always as last element
            };

    	
        /**
        * The current state of active object.
        */ 
        TWapiState iState;	

	    /**
	    * Pointer to the AM tools class.
	    */
        abs_eap_am_tools_c* iAmTools;
	    
        /*
        * Array of References:
        */
	    eap_array_c<ec_cs_data_c> iInReferences;

	    /**
	    * Array of reference & datablocks:
	    */ 
	    eap_array_c<ec_cs_data_c> iReferencesAndDataBlocks;

	    /**
	    * EAPOL status that is returned to common side.
	    */ 
	    eap_status_e iWapiCompletionStatus;

	    /*
	    * Variable describes the pending operation of
	    * certificate store.
	    */ 
	    ec_cs_pending_operation_e iCsPendingOperation;


	    /**
	    * Pointer to the lower layer in the stack.
	    */
        abs_wapi_am_core_c* iPartner;


        /**
        *
        */ 
        abs_ec_am_certificate_store_c* iCertStorePartner;
        
        /*
        * Certificate store implements database store for certificate data.
        */ 
        CCertificateStoreDatabase* iCertificateStoreDb;
        
        /**
        * Password of certificate store.
        */ 
    	eap_variable_data_c iCsPassword;

	    /*
        * Boolean flag to make sure that if objects are deleted in cancel,
	    * we don't use them anymore.
	    */
	    TBool iCancelCalled;


#if defined( WAPI_USE_UI_NOTIFIER )
    	
        /**
        * Notifier. It acts as a service provider.
        */
        RNotifier iNotifier; 
              
         /**
         * Data sent from AO to notifier plugin.
         */
         TWapiUiNotifierInfo* iNotifierDataToUser;

         /**
         * Packaged data sent from AO to notifier plugin.
         */
         TPckg<TWapiUiNotifierInfo>* iNotifierDataPckgToUser;	

         /**
         * Data from notifier plugin to AO.
         */
         TWapiUiNotifierInfo* iNotifierDataFromUser;

 	    /**
         * Packaged data from notifier plugin to AO.
         */
 	    TPckg<TWapiUiNotifierInfo>* iNotifierDataPckgFromUser;	
   	
#endif // WAPI_USE_CERT_FILE_PASSWORD
 	    
	    //--------- TODO: DELETE NOT USED MEMBERS ------
	    
	    u32_t m_authentication_counter;

	    u32_t m_successful_authentications;

	    u32_t m_failed_authentications;

	    bool m_is_valid;

	    bool m_is_client;	

	    bool m_first_authentication;

	    bool m_self_disassociated;

	    eap_variable_data_c * m_ssid;

	    eap_am_network_id_c* m_receive_network_id;

	    eap_file_config_c* m_fileconfig;
	    wapi_completion_operation_e iCompletionOperation;
	
	    // For MMETEL connection.
        RTelServer iServer;
        RMobilePhone iPhone;
    
        // Stores the last queried Phone identities like manufacturer, model, 
        // revision and serial number
        RMobilePhone::TMobilePhoneIdentityV1 iDeviceId; 
    	
        // Tells if MMETEL is connected already or not.
        TBool iMMETELConnectionStatus;  
    
        eap_variable_data_c* iWapiDeviceSeed;
        
        /* Status for the WAPICertificates class Active object */
        TRequestStatus* iWapiCertsStatus;
        
        // The pointers to store the pointer to the certificate store array 
        // for the wapicertificates label reading functionality
        RArray<TBuf<KCsMaxWapiCertLabelLen> > **iUserCerts;
        RArray<TBuf<KCsMaxWapiCertLabelLen> > **iCACerts;
        RArray<TBuf8<KMaxIdentityLength> > **iUserCertsData;
        RArray<TBuf8<KMaxIdentityLength> > **iCACertsData;
    
        RArray<SWapiCertEntry> iCertArray;
        
        TBool iGetAll;
        
        eap_variable_data_c iEapVarData;

        RArray<TBuf8<KMaxFileName> > iImportedFilenames; 
	//--------------------------------------------------
    }; // class wapi_am_core_symbian_c

#endif //#if !defined(_WAPI_AM_CORE_SYMBIAN_H_)

//--------------------------------------------------



// End of file
