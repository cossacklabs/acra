package logging

const (
	// 100 .. 200 some events
	EventCodeGeneral = 100

	// 500 .. 600 errors
	EventCodeErrorGeneral    = 500
	EventCodeErrorWrongParam = 501

	// processes
	EventCodeErrorCantStartService             = 505
	EventCodeErrorCantForkProcess              = 506
	EventCodeErrorWrongConfiguration           = 507
	EventCodeErrorCantReadServiceConfig        = 508
	EventCodeErrorCantCloseConnectionToService = 509

	// keys
	EventCodeErrorCantInitKeyStore = 510
	EventCodeErrorCantReadKeys     = 511

	// system events
	EventCodeErrorCantGetFileDescriptor     = 520
	EventCodeErrorCantOpenFileByDescriptor  = 521
	EventCodeErrorFileDescriptionIsNotValid = 522
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

	// AcraWebconfig
	EventCodeErrorCantReadTemplate        = 550
	EventCodeErrorRequestMethodNotAllowed = 551
	EventCodeErrorCantParseRequestData    = 552
	EventCodeErrorCantGetCurrentConfig    = 553
	EventCodeErrorCantSetNewConfig        = 554
	EventCodeErrorCantHashPassword        = 555
	EventCodeErrorCantGetAuthData         = 556
	EventCodeErrorCantParseAuthData       = 557
	EventCodeErrorCantDumpConfig          = 558

	// acracensor
	EventCodeErrorCensorQueryIsNotAllowed = 560
	EventCodeErrorCensorSetupError        = 561
	EventCodeErrorCensorSecurityError     = 562

	// response connector
	EventCodeErrorResponseConnectorCantWriteToDB      = 570
	EventCodeErrorResponseConnectorCantReadFromClient = 571
	EventCodeErrorResponseConnectorCantWriteToClient  = 572
	EventCodeErrorResponseConnectorCantReadFromServer = 573
	EventCodeErrorResponseConnectorCantWriteToServer  = 574
	EventCodeErrorResponseConnectorCantProcessColumn  = 575
	EventCodeErrorResponseConnectorCantProcessRow     = 576

	// decryptor
	EventCodeErrorCantInitDecryptor                          = 580
	EventCodeErrorDecryptorCantDecryptBinary                 = 581
	EventCodeErrorDecryptorCantSkipBeginInBlock              = 582
	EventCodeErrorDecryptorCantHandleRecognizedPoisonRecord  = 583
	EventCodeErrorDecryptorCantInitializeTLS                 = 584
	EventCodeErrorDecryptorCantSetDeadlineToClientConnection = 585
	EventCodeErrorDecryptorCantDecryptSymmetricKey           = 586

	// api
	EventCodeErrorCantGenerateZone = 590

	// mysql processing
	EventCodeErrorProtocolProcessing = 600
)
