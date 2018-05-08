import { Component } from '@angular/core';
import { InvoiceService } from '../../../@core/data/invoice.service';

@Component({
  selector: 'ngx-new-invoice-form',
  templateUrl: './invoice-form.component.html',
  styleUrls: ['./invoice-form.component.scss'],
})
export class InvoiceFormComponent {

  customers: any[];
  showNewCustomer: boolean = false;

  constructor(private invoiceService: InvoiceService) {

    this.invoiceService
      .customers()
      .then(result => this.customers = result)
      .catch(error => console.log(error));
  }

  toggleNewCustomerDialog() {
    this.showNewCustomer = !this.showNewCustomer;
  }
}
