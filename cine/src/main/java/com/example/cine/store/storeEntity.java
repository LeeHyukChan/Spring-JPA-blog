package com.example.cine.store;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
@Table(name="PRDT_LIST")
public class storeEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private String prdtcd;
	
	@Column
	private int prdtcategory;
	
	@Column
	private String prdtnm;
	
	@Column
	private String prdtcont;
	
	@Column
	private String prdtimg;
	
	@Column
	private String prdtquant;
	
	@Column
	private String prdtsaldate;
	
	@Column
	private String prdtexpdate;
	
	@Column
	private String prdtprice;
	
}
