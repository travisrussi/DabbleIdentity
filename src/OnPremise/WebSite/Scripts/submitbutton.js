$( function () {
	// toggle the submitbutton's class when the user is registering||logging in

	$( '#create-check' ).on( 'change', function ( e ) {
		var checkbox = $( this );
		if ( checkbox.is( ':checked' ) ) {
			$( '.submitbutton' ).eq( 0 ).addClass( 'new' );
			$( '.h5-matchingpassword' ).prop( 'required', true );
		} else {
			$( '.submitbutton' ).eq( 0 ).removeClass( 'new' );
			$( '.h5-matchingpassword' ).val( '' ).prop( 'required', false );
		}

		// toggles everything else
		$( '.registertoggle' ).slideToggle().removeClass( 'hidden' );
	} );
} );

$( function () {
	// toggle the submitbutton's class when the user is registering||logging in

	$( '#email-change' ).on( 'change', function ( e ) {
		var checkbox = $( this );
		// toggles everything else
		$( '.emailchangetoggle' ).slideToggle().removeClass( 'hidden' );
	} );
} );

$( function () {
	// toggle the submitbutton's class when the user is registering||logging in

	$( '#password-change' ).on( 'change', function ( e ) {
		var checkbox = $( this );
		// toggles everything else
		$( '.passwordchangetoggle' ).slideToggle().removeClass( 'hidden' );
	} );
} );

