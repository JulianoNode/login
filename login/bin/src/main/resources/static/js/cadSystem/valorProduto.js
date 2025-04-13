$(document).ready(function() {
	moment.locale('pt-BR');
	var table = $('#table-valorProdutoCrud').DataTable({

		"language": { "url": "//cdn.datatables.net/plug-ins/1.13.2/i18n/pt-BR.json" },
		searching: true,
		order: [[1, "asc"]],
		lengthMenu: [5, 10, 20],
		processing: true,
		serverSide: true,
		responsive: true,
		ajax: {
			url: '/valorProdutos/datatables/server',
			data: 'data'
		},
		columns: [
			{ data: 'id' },

			{
                            orderable: false,
                            data: 'valor',
                            "render": function(valor) {
                                return '<label style="font-size: 16px;">R$: </label>' + valor;
                            }

			},

			{
                            orderable: false,
                            data: 'id',
                            "render": function(id) {
                                return '<a class="btn btn-success btn-sm btn-block" href="/valorProdutos/editar/' +
                                id + '" role="button"><i class="fas fa-edit"></i></a>';
                            }
			},
			{
                            orderable: false,
                            data: 'id',
                            "render": function(id) {
                            	return '<a class="btn btn-danger btn-sm btn-block" href="/valorProdutos/excluir/' +
                                id + '" role="button" data-toggle="modal" data-target="#confirm-modal"><i class="fas fa-times-circle"></i></a>';
                            }
			}
		]
	});
});




