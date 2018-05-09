import { Injectable } from '@angular/core';
import { Observable } from 'rxjs/Observable';
import { HttpModule } from '@angular/http';
import 'rxjs/add/observable/of';
import 'rxjs/add/operator/toPromise';
import { of } from 'rxjs/observable/of';
import { BehaviorSubject } from 'rxjs/BehaviorSubject';
import { asObservable } from './asObservable';
import { Headers, Response, Http, RequestOptions, URLSearchParams } from '@angular/http';
import * as appConfig from '../../../appSettings.json';

@Injectable()
export class InvoiceService {

  private _invoices: BehaviorSubject<Array<any>> = new BehaviorSubject(Array([]));
  private _customers: BehaviorSubject<Array<any>> = new BehaviorSubject(Array([]));

  private apiUrl = appConfig['apiUrl'];
  private userArray: any[];
  private twitterUser: any = {};
  private countryName: string;
  private filtered: any[] = [];

  constructor(private http: Http) {
    //this.loadInvoices();
  }

invoices() {
  return this.http.get(this.apiUrl)
    .toPromise()
    .then(this.extractData)
    .catch(this.handleError);
  }

  customers(): Promise<any>{
    return this.http.get(this.apiUrl + "customers")
      .toPromise()
      .then(this.extractData)
      .catch(this.handleError);
  }

  /*data: [
    { value: 335, name: 'Germany' },
    { value: 310, name: 'France' },
    { value: 234, name: 'Canada' },
    { value: 135, name: 'Russia' },
    { value: 1548, name: 'USA' },
  ]*/

  echartData(): Promise<any>{

    let data = new Array();

    return this.http.get(this.apiUrl + "chart-data")
      .toPromise()
      .then(this.extractData)
      .catch(this.handleError);
  }

  private extractData(res: Response) {
    let body = res.json();
    return body || {};
  }

  handleError(error: any): Promise<any> {
    console.error('An error occurred', error);
    return Promise.reject(error.message || error);
  }

  loadInvoices() {
    this.http.get(this.apiUrl).subscribe(res => {
      this._invoices = res.json();
    }, error => { console.error(error) });

  }

}
