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
	EventCodeErrorCantGetFileDescriptor     = 520
	EventCodeErrorCantOpenFileByDescriptor  = 521
	EventCodeErrorFileDescriptionIsNotValid    = 522
	EventCodeErrorCantRegisterSignalHandler = 523

	// transport / networks
	EventCodeErrorCantStartListenConnections = 530
	EventCodeErrorCantStopListenConnections  = 531
	EventCodeErrorTransportConfiguration     = 532
	EventCodeErrorCantAcceptNewConnections   = 533
	EventCodeErrorCantStartConnection        = 534
	EventCodeErrorCantHandleSecureSession    = 535
	EventCodeErrorCantCloseConnection        = 536
	EventCodeErrorCantInitClientSession      = 537
	EventCodeErrorCantWrapConnection         = 538
	EventCodeErrorConnectionDroppedByTimeout = 539

	// database
	EventCodeErrorCantConnectToDB       = 540
	EventCodeErrorCantCloseConnectionDB = 541
	EventCodeErrorCantInitDecryptor     = 542

	// config UI
	EventCodeErrorCantReadTemplate     = 550
	EventCodeErrorRequestMethodNotAllowed = 551
	EventCodeErrorCantParseRequestData = 552
	EventCodeErrorCantGetCurrentConfig = 553
	EventCodeErrorCantSetNewConfig     = 5543
)
