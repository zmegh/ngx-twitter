import { Component, Renderer } from '@angular/core';

@Component({
  selector: 'ngx-custom-smart-table-button',
  template: `<div class="dropdown" ngbDropdown>
      <button class="btn btn-secondary btn-demo" type="button" ngbDropdownToggle>
      <i class="nb-gear"></i>
        Actions
      </button>
      <ul class="dropdown-menu" ngbDropdownMenu>
        <li class="dropdown-item">Send Invoice</li>
        <li class="dropdown-item" (click)="openCheckout()">Pay With Card</li>
        <li class="dropdown-item">Add Charge</li>
        <li class="dropdown-item">Add Credit</li>
        <li class="dropdown-item">Archive</li>
      </ul>
    </div>`,
})
export class CustomSmartTablebuttonComponent {
  globalListener: any;

  constructor(private renderer: Renderer) { }

  openCheckout() {
    var handler = (<any>window).StripeCheckout.configure({
      key: 'pk_test_oi0sKPJYLGjdvOXOM8tE8cMa',
      locale: 'auto',
      token: function (token: any) {
        // You can access the token ID with `token.id`.
        // Get the token ID to your server-side code for use.
      }
    });


    handler.open({
      name: 'Demo Site',
      description: '2 widgets',
      amount: 2000
    });

    this.globalListener = this.renderer.listenGlobal('window', 'popstate', () => {
      handler.close();
    });

  }

  ngOnDestroy() {
    if (this.globalListener) {
      this.globalListener();
    }
  }

}
