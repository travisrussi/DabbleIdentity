// plugin declaration
(function ($, window, document) {
	var pluginName = "hints",
		defaults = {
			toggleclass: "hidden",
			template: '<span class="hint_box"></span>'
		},
		settings; // scoped!

	// The actual plugin constructor
	function Plugin( element, options ) {
		this.input = element;
		this.$input = $( element );
		this.element = {};
		this.$element = {};

		this.options = $.extend( {}, defaults, options );

		this._defaults = defaults;
		this._name = pluginName;

		this.init();
	}

	Plugin.prototype = {

		init: function () {
			this.$element = $( this.options.template ).html( this.$input.data( 'hint' ) );
			this.$input.after( '<div></div>' );
			this.$input.after( this.$element );

			// position the element correctly (todo: make this optional)
			this.$element.css( {
				'margin-top': ( this.$input.outerHeight() / 2 ) - ( this.$element.outerHeight() / 2 ) + 'px'
			} );
		},

		show: function () {
			this.$element.removeClass( this.options.toggleclass );

			// dirty fix for IE8 not updating UI
			$( '#main-container' ).css( 'opacity', 0.9999 );
		},
		hide: function () {
			this.$element.addClass( this.options.toggleclass );
			$( '#main-container' ).css( 'opacity', 1 );
		}

	};


	// event handlers
	var focusHandler = function ( e ) {
		var _this = e !== undefined ? e.target : this;
		if ( !$.data( _this, "plugin_" + pluginName ) && $( _this ).data( 'hint' ) && $( _this ).data( 'hint' ).length ) {
			// create new instance
			$.data( _this, "plugin_" + pluginName, new Plugin( _this, settings ) );
		} else if ( $.data( _this, "plugin_" + pluginName ) ) {
			// reuse existing instance protected from repeat
			$.data( _this, "plugin_" + pluginName ).show();
		}
	},
		blurHandler = function ( e ) {
			var _this = e !== undefined ? e.target : this;
			if ( $.data( _this, "plugin_" + pluginName ) ) {
				$.data( _this, "plugin_" + pluginName ).hide();
			}
		};

	$.fn[pluginName] = function ( options ) {
		return this.each( function () {

			// save the options, there's no var statement here on purpose!
			settings = options;

			$( '[data-hint]', this ).each( function () {
				$( this ).bind( 'focus', focusHandler );
				$( this ).bind( 'blur', blurHandler );
			} );

		} );
	};

} )( jQuery, window, document );


// plugin instantiation
$( function () {
	// .hinted is a <form> or other type of container that has hintable inputs/elements
	$( '.hinted' ).hints();
} );