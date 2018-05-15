export class invoice {
  id: number;
  invoiceDate: string;
  customerId: number;
  service: string;
  statusId: number;
  totalAmount: number;
  amountDue: number;

  constructor(
    id: number,
    invoiceDate: string,
    customerId: number,
    service: string,
    statusId: number,
    totalAmount: number,
    amountDue: number) {

    this.id = id;
    this.invoiceDate = invoiceDate;
    this.customerId = customerId;
    this.service = service;
    this.statusId = statusId;
    this.totalAmount = totalAmount;
    this.amountDue = amountDue;
  }
}
