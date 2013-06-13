// plugin instantiation
$(function () {

	$.h5Validate.addPatterns( {
		matchingpassword: ( function () {
			return $( '#password1' ).val();
		} )()
	} );

	// .validate is a <form> or other type of container that has validatable inputs
	$( '.validate' ).h5Validate( {
		errorClass: 'error',
		validClass: 'valid'
	} );

	$( '#password1' ).on( 'change', function () {
		$.h5Validate.addPatterns( {
			matchingpassword: ( function () {
				return $( '#password1' ).val();
			} )()
		} );

	} );
} );