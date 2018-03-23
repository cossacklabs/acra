package logging

const (
	// 100 .. 200 some events
	EventCodeGeneral = 100

	// 500 .. 600 errors
	EventCodeErrorGeneral                    = 500

	// processes
	EventCodeErrorCantStartService             = 505
	EventCodeErrorCantForkProcess              = 506
	EventCodeErrorWrongConfiguration           = 507
	EventCodeErrorCantReadServiceConfig        = 508
	EventCodeErrorCantCloseConnectionToService = 509

	// keys
	EventCodeErrorCantInitKeyStore           = 510
	EventCodeErrorCantReadKeys               = 511

	// system events
	EventCodeErrorCantGetFileDescriptor      = 520
	EventCodeErrorCantRegisterSignalHandler  = 521

	// transport / networks
	EventCodeErrorCantStartListenConnections = 530
	EventCodeErrorTransportConfiguration     = 531
	EventCodeErrorCantAcceptNewConnections   = 532
	EventCodeErrorCantStartConnection        = 533
	EventCodeErrorCantHandleSecureSession    = 534

	// database
	EventCodeErrorCantConnectToDB = 540
	EventCodeErrorCantCloseConnectionDB = 541
	EventCodeErrorCantInitDecryptor = 542
)
