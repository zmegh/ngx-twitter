import { Component } from '@angular/core';
import { InvoiceService } from '../../../@core/data/invoice.service';
import { invoice } from "../../../@core/models/invoice.model";

@Component({
  selector: 'ngx-new-invoice-form',
  templateUrl: './invoice-form.component.html',
  styleUrls: ['./invoice-form.component.scss'],
})
export class InvoiceFormComponent {

  customers: any[];
  showNewCustomer: boolean = false;
  invoice = new invoice(232, '09/23/2014', 1, "coding something awesome", 4, 5400, 5400)
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
